/*
 * Copyright (C) 2013 - Zifei Tong <soariez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <BPatch.h>
#include <BPatch_object.h>
#include <BPatch_function.h>
#include <BPatch_point.h>
#define __STDC_LIMIT_MACROS

#define MAX_STR_LEN 40

extern "C" {
#include <link.h>
#include "ust-app.h"
#include "ust-instrument.h"
#include "ust-events.h"
#include <lttng/tracepoint.h>
#include <lttng/ringbuffer-config.h>

void add_int_event_field( struct lttng_event_di_field *field, char *name)
{
	struct lttng_event_di_field f = {
		.name = name,
		.type = __type_integer(int, LITTLE_ENDIAN, 10, none),
		.nowrite = 0
	};

	memcpy(field, &f, sizeof(struct lttng_event_di_field));
}

void add_float_event_field( struct lttng_event_di_field *field, char *name)
{
	struct lttng_event_di_field f = {
		.name = name,
		.type = __type_float(float),
		.nowrite = 0
	};

	memcpy(field, &f, sizeof(struct lttng_event_di_field));
}

void add_char_event_field( struct lttng_event_di_field *field, char *name)
{
	struct lttng_event_di_field f = {
		.name = name,
		.type = __type_integer(char, LITTLE_ENDIAN, 10, none),
		.nowrite = 0
	};

	memcpy(field, &f, sizeof(struct lttng_event_di_field));
}
}
namespace {

BPatch_object *find_match_object(BPatch_image *image, const char *path)
{
	std::vector<BPatch_object *> objects;
	image->getObjects(objects);
	for (int i = 0; i < objects.size(); i++) {
		if (objects[i]->pathName() == path) {
			return objects[i];
		}
	}
	return NULL;
}

int instrument_process(BPatch_process *process,
		BPatch_image *image,
		std::vector<BPatch_point *> &points,
		struct tracepoint *tracepoint)
{
	std::vector<BPatch_function *> probes;

	image->findFunction(__ust_stringify(LTTNG_DYNAMIC_TRACEPOINT), probes);
	if (probes.size() == 0) {
		ERR("Probe callback function not found in app process");
		return -1;
	}
	if (probes.size() > 1) {
		ERR("Multiple instances of probe callback function found in app process");
		return -1;
	}

	std::vector<BPatch_snippet *> args;
	BPatch_constExpr tracepoint_ptr(tracepoint);
	args.push_back(&tracepoint_ptr);
	BPatch_funcCallExpr call_probe(*probes[0], args);

	for (int i = 0; i < points.size(); i++) {
		if (!process->insertSnippet(call_probe, *points[i])) {
			return -1;
		}
	}
	return 0;
}

int instrument_process_tracef(BPatch_process *process,
		BPatch_image *image,
		std::vector<BPatch_point *> &points,
		BPatch_function *function)
{
	std::vector<BPatch_function *> probes;
	image->findFunction("_lttng_ust_tracef", probes);
	if(probes.size() == 0)
	{
		DBG("********tracef function not found");
	}
	std::vector<BPatch_snippet *> args, tmp_args;
	std::string fmt("params: ");
	vector<BPatch_localVar *> *params = function->getParams();
	if(params->size() == 0)
	{
	    DBG("*******No parameter found");
	    fmt=std::string("NO PARAMETER FOUND");
	}
	else
	{

	    for(unsigned int i = 0; i < params->size(); ++i )
	    {
		    tmp_args.push_back(new BPatch_constExpr((*params)[i]->getName()));
		    //Push the type of the next argument
		    switch((*params)[i]->getType()->getDataClass())
		    {
			    case BPatch_dataScalar:
			    {
				    string typeName = (*params)[i]->getType()->getName();
				    if(typeName == "char")
				    {
				    	    fmt.append("char %s = \'%c\'");
					    tmp_args.push_back(new BPatch_paramExpr(i));
				    }
				    else if (typeName == "short int")
				    {
				    	    fmt.append("short int %s = %d");
					    tmp_args.push_back(new BPatch_paramExpr(i));
				    }
				    else
				    {
				    	    fmt.append("int %s = %d");
					    tmp_args.push_back(new BPatch_paramExpr(i));
				    }
				    break;
			    }
			    case BPatch_dataPointer:
			    {
				    string typeName = (*params)[i]->getType()->getConstituentType()->getName();
				    if(typeName == "char")
				    {
				    	    fmt.append("char *%s = \"%s\"");
					    tmp_args.push_back(new BPatch_paramExpr(i));
				    }
				    else
				    {
				    	    fmt.append("int *%s = %p");
					    tmp_args.push_back(new BPatch_paramExpr(i));
				    }
				    break;
			    }
			    default:
			    {
				    cout<<"Dataclass unsupported"<<endl;
				    fmt.append("%d");
				    args.push_back(new BPatch_constExpr(99999999));
				    break;
			    }
		    }
		    fmt.append(", ");
	    }
	}
	args.push_back(new BPatch_constExpr(fmt.c_str()));
	args.reserve(args.size()+tmp_args.size());
	args.insert(args.end(), tmp_args.begin(), tmp_args.end());

	cout<<"****"<<fmt<<": "<<args.size()<<endl;
	BPatch_funcCallExpr call_tracef(*probes[0], args);
	for (int i = 0; i < points.size(); i++) {
		if (!process->insertSnippet(call_tracef, *points[i])) {
			return -1;
		}
		}
	return 0;
}
int register_tp_from_mutatee(BPatch_process *handle, BPatch_variableExpr *tp, vector<BPatch_snippet *> *seq)
{
	DBG("Inserting tracepoint register call in mutatee");
	vector<BPatch_function*> functions;
	BPatch_image *image = handle->getImage();
	std::vector<BPatch_snippet *> args;

	image->findFunction("tracepoint_register", functions);
	if(functions.size() == 0)
	{
		ERR("tracepoint_register function not found");
		return -1;
	}

	args.push_back(new BPatch_constExpr( tp->getBaseAddr()));
	BPatch_funcCallExpr *tp_register_call =
			new BPatch_funcCallExpr(*functions[0], args);

	seq->push_back(tp_register_call);
	return 0;
}

int probe_register_from_mutatee(BPatch_process *handle, BPatch_variableExpr *probe,
		vector<BPatch_snippet *> *seq)
{
	DBG("Inserting probe register call in mutatee");
	vector<BPatch_function*> functions;
	BPatch_image *image = handle->getImage();
	std::vector<BPatch_snippet *> args;

	image->findFunction("lttng_probe_register", functions);
	if(functions.size() == 0)
	{
		ERR("lttng_probe_register function not found");
		return -1;
	}

	args.push_back(new BPatch_constExpr(probe->getBaseAddr()));
	BPatch_funcCallExpr *probe_register_call =
			new BPatch_funcCallExpr(*functions[0], args);
	seq->push_back(probe_register_call);

	return 0;
}

int complete_registration(BPatch_process *handle, vector<BPatch_snippet*> *seq ,BPatch_variableExpr *isRegistered)
{
	DBG("Turn the enable flag ON so the tracepoint is actived");
	BPatch_arithExpr completed(BPatch_assign, *isRegistered,
			BPatch_arithExpr(BPatch_plus, *isRegistered, BPatch_constExpr(1)));

	seq->push_back(&completed);

	vector<BPatch_function*> fake_function;
	BPatch_image *image = handle->getImage();
	image->findFunction("lttng_ust_fake_function", fake_function);
	if(fake_function.size() == 0)
	{
		ERR("lttng_ust_fake_function function not found");
		return -1;
	}
	DBG("Insert the sequence of registration calls and the flag enabling at the fake function location");
	handle->insertSnippet(BPatch_sequence(*seq), fake_function[0]->findPoint(BPatch_entry)[0]);
}

int instrument_function_entry(BPatch_process *process,
			const char *symbol, const char *event_name, bool is_entry)
{
	DBG("Instrumenting entry of function \"%s\"", symbol);
	process->loadLibrary("/home/frdeso/projets/runtime-ust/tp.so");
	process->loadLibrary("/usr/local/lib/liblttng-ust.so");

	BPatch_variableExpr *nameExpr = process->malloc(sizeof(char) * MAX_STR_LEN);
	BPatch_variableExpr *signExpr = process->malloc(sizeof(char) * MAX_STR_LEN);
	BPatch_variableExpr *provExpr = process->malloc(sizeof(char) * MAX_STR_LEN);

	/*
	 * Format the name, signature and provider of the event
	 */
	char *nameArr =(char *) malloc(sizeof(char) * MAX_STR_LEN);
	char *signArr =(char *) malloc(sizeof(char) * MAX_STR_LEN);
	char *provArr =(char *) malloc(sizeof(char) * MAX_STR_LEN);
#warning "free these ^"
	if(is_entry)
	{
		sprintf(nameArr,"%s_entry", event_name);
	}
	else
	{
		sprintf(nameArr,"%s_exit", event_name);
	}
	strncpy(provArr, nameArr, MAX_STR_LEN);
	signArr = strchr(provArr,':');
#warning "might fail"
	signArr[0] = '\0';
	signArr += 1;


	nameExpr->writeValue((char *) nameArr, MAX_STR_LEN, false);
	signExpr->writeValue((char *) signArr, MAX_STR_LEN, false);
	provExpr->writeValue((char *) provArr, MAX_STR_LEN, false);

	/*
	 * Create a tracepoint structure and copy it in the
	 * mutatee address space.
	 */

	struct tracepoint t = {
		.name = (const char*) nameExpr->getBaseAddr(), //Does this work?
		.state = 0,
		.probes = NULL,
		.tracepoint_provider_ref = NULL,
		.signature = (const char*) signExpr->getBaseAddr(),//Does this work?
	};

	BPatch_variableExpr *tpExpr = process->malloc(sizeof(struct tracepoint));
	tpExpr->writeValue((void *) &t, sizeof(struct tracepoint), false);

	/*
	 *Call the tracepoint_register function rightaway
	 */
	vector<BPatch_snippet *> register_call_sequence;
	register_tp_from_mutatee(process, tpExpr, &register_call_sequence);

	/*
	 * Construct a lttng_event_di_field array to contain one field per parameter
	 */
	vector<BPatch_function*>  field_fcts, symbol_fcts;
	BPatch_function *function;

	BPatch_image *image = process->getImage();
	image->findFunction(symbol, symbol_fcts);
	if(symbol_fcts.size() <= 0)
	{
		DBG("Symbol %s not found in process", symbol);
		return -1;
	}

	if(symbol_fcts.size() > 0)
	{
		DBG("Multiple symbol %s found in process. Will be using the first one", symbol);
	}

	function = symbol_fcts[0];

	vector<BPatch_localVar *> *params = function->getParams();
	struct lttng_event_di_field *event_fields;
	int nb_field = params->size();
	event_fields = (struct lttng_event_di_field* ) malloc(sizeof(struct lttng_event_di_field)*nb_field);
	DBG("nb field=%d", nb_field);

	int __event_len = 0;


	for(int i = 0;i < nb_field ; ++i)
	{
		BPatch_variableExpr* fieldNameExpr = process->malloc(sizeof(char) * MAX_STR_LEN);
		fieldNameExpr->writeValue((char *)(*params)[i]->getName(), MAX_STR_LEN);

		// Add a field depending on the type of the parameter
		switch((*params)[i]->getType()->getDataClass())
		{
		case BPatch_dataScalar:
		{
			string typeName = (*params)[i]->getType()->getName();
			if(typeName == "char")
			{
				add_char_event_field(&event_fields[i],
						(char *) fieldNameExpr->getBaseAddr());
				__event_len
					+= (lib_ring_buffer_align(__event_len, lttng_alignof(char))
					+ sizeof(char));
				image->findFunction("event_write_char", field_fcts);
#warning "might fail"
			}
			else
			{
				add_int_event_field(&event_fields[i],(char *) fieldNameExpr->getBaseAddr());
				__event_len
					+= (lib_ring_buffer_align(__event_len, lttng_alignof(int))
					+ sizeof(int));
				image->findFunction("event_write_int", field_fcts);
#warning "might fail"
			}
			break;
		}
		default:
		{
			DBG("Dataclass unsupported");
			break;
		}
		}
	}

	BPatch_variableExpr *event_fieldsExpr;
	if(nb_field > 0)
	{
		event_fieldsExpr = process->malloc(sizeof(struct lttng_event_field) * nb_field);
		event_fieldsExpr->writeValue(event_fields, sizeof(struct lttng_event_field) * nb_field, false);
	}
	else
	{
		/*
		 * Event_fields should be null because the number of field is zero
		 */
		assert(event_fields);
		event_fieldsExpr = process->malloc(*(image->findType("int")));
		event_fieldsExpr->writeValue(&event_fields, sizeof(int), false);
		DBG("baseaddr=%p", event_fieldsExpr->getBaseAddr())
	}

	/*
	 * Create event description, this description must be add to an array for the registration
	 * So we have to allocate an array of event description in the mutatee.
	 */

	struct lttng_event_desc event_desc = {
		.name = (const char*) nameExpr->getBaseAddr(),
		.probe_callback = (void (*)()) 1337, //FIXME: must set the probe callback to none null value but is not used
		.ctx = NULL,
		.fields = (const struct lttng_event_field *) event_fieldsExpr->getBaseAddr(),
		.nr_fields = (unsigned int) nb_field,
		.loglevel = NULL,
		.signature = (const char*) signExpr->getBaseAddr(),
	};

	BPatch_variableExpr *event_descExpr = process->malloc(sizeof(struct lttng_event_desc));
	event_descExpr->writeValue(&event_desc, sizeof(struct lttng_event_desc), false);

	BPatch_variableExpr *event_descArrayExpr = process->malloc(sizeof(struct lttng_event_desc*));
	unsigned long addr = (unsigned long) event_descExpr->getBaseAddr();
	event_descArrayExpr->writeValue(&addr,  sizeof(struct lttng_event_desc*), false);

	/*
	 * Create probe description and register it.
	 */
	struct lttng_probe_desc desc = {
		.provider = (const char*) provExpr->getBaseAddr(),
		.event_desc = (const struct lttng_event_desc **) event_descArrayExpr->getBaseAddr(),
		.nr_events = 1,
		.head = { NULL, NULL },
		.lazy_init_head = { NULL, NULL },
		.lazy = 0,
		.major = LTTNG_UST_PROVIDER_MAJOR,
		.minor = LTTNG_UST_PROVIDER_MINOR,
		.type = LTTNG_PROBE_INSTRUMENT,
	};

	BPatch_variableExpr *probe_descExpr = process->malloc(sizeof(struct lttng_probe_desc));
	probe_descExpr->writeValue(&desc, sizeof(struct lttng_probe_desc), false);

	probe_register_from_mutatee(process, probe_descExpr, &register_call_sequence);

	BPatch_variableExpr *isRegistered = process->malloc(*(image->findType("int")));
	complete_registration(process, &register_call_sequence, isRegistered);
	/*
	 * We are now ready to insert the tracepoint in the running binary.
	 * This is done in three step.
	 * 	1. Allocate and initialize the context in the mutatee
	 * 	2. Register one call expression for each paramaters
	 * 	3. Commit the event
	 */

	std::vector<BPatch_snippet *> args;
	std::vector<BPatch_function *> init_ctx_fct, commit_fct;
	std::vector<BPatch_snippet *> call_sequence;

	/*
	 * Allocate context
	 */

	BPatch_variableExpr *ctxExpr = process->malloc(sizeof(struct lttng_ust_lib_ring_buffer_ctx));

	/*
	 * Initializing context
	 */
	image->findFunction("init_ctx", init_ctx_fct);
#warning "might fail"
	args.push_back(new BPatch_constExpr(ctxExpr->getBaseAddr()));
	args.push_back(new BPatch_constExpr(tpExpr->getBaseAddr()));
	args.push_back(new BPatch_constExpr( __event_len ));
	args.push_back(isRegistered);
	BPatch_funcCallExpr init_ctx_fct_call(*(init_ctx_fct[0]), args);
	call_sequence.push_back(&init_ctx_fct_call);

	args.clear();

	/*
	 * Add call expression for each parameter
	 */
	for(int i = 0 ; i < nb_field ; ++i)
	{
		args.push_back(new BPatch_constExpr(ctxExpr->getBaseAddr()));
		args.push_back(new BPatch_constExpr(tpExpr->getBaseAddr()));
		args.push_back(new BPatch_constExpr( __event_len ));
		args.push_back(new BPatch_paramExpr(i));
		args.push_back(isRegistered);
		BPatch_funcCallExpr *field_call = new BPatch_funcCallExpr(*(field_fcts[i]), args);
		call_sequence.push_back(field_call);

		args.clear();
	}


	/*
	 * Commit the event
	 */

	args.push_back(new BPatch_constExpr(ctxExpr->getBaseAddr()));
	args.push_back(new BPatch_constExpr(tpExpr->getBaseAddr()));
	args.push_back(isRegistered);
	image->findFunction("event_commit", commit_fct);
#warning "might fail"
	BPatch_funcCallExpr event_commit_call(*(commit_fct[0]), args);
	call_sequence.push_back(&event_commit_call);

	vector<BPatch_point *>* function_entry_points = function->findPoint(BPatch_entry);
	process->insertSnippet(BPatch_sequence(call_sequence), *(*function_entry_points)[0]);
	args.clear();
	field_fcts.clear();
}

/*
 * Check if user set DYNINSTAPI_RT_LIB environment variable.
 * If not, guess the path of dyninst RT lib form the path of libdyninstAPI.so.
 * Inspired form systemtap source code.
 */
int guess_dyninst_rt_lib_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	char **dyninst_rt_lib = (char **) data;
	if (strstr(info->dlpi_name, "libdyninstAPI.so")) {
		*dyninst_rt_lib = (char *) malloc(strlen(info->dlpi_name) + 1);
		strcpy(*dyninst_rt_lib, info->dlpi_name);
	}
}

void guess_dyninst_rt_lib(char **dyninst_rt_lib)
{
	char *pos;
	dl_iterate_phdr(guess_dyninst_rt_lib_cb, dyninst_rt_lib);

	if (*dyninst_rt_lib && (pos = strstr(*dyninst_rt_lib, ".so"))) {
		/* Shift string to make room for "_RT" */
		strcpy(pos + 3, pos);
		strncpy(pos, "_RT", 3);
	}
}

int check_dyninst_rt_lib()
{
	const char dyninst_rt_lib_env[] = "DYNINSTAPI_RT_LIB";
	char *dyninst_rt_lib;
	int ret = 0;

	dyninst_rt_lib = getenv(dyninst_rt_lib_env);
	if (dyninst_rt_lib) {
		goto end;
	}

	guess_dyninst_rt_lib(&dyninst_rt_lib);
	if (dyninst_rt_lib && !access(dyninst_rt_lib, F_OK)) {
		ret = setenv(dyninst_rt_lib_env, dyninst_rt_lib, 0);
		free(dyninst_rt_lib);
		goto end;
	}

end:
	return ret;
}

}
int ust_instrument_probe(struct ust_app *app,
		const char *object_path,
		const char *name,
		struct lttng_ust_instrument_tracepoint_attr *tracepoint,
		enum lttng_ust_instrumentation instrumentation,
		uint64_t addr,
		const char *symbol,
		uint64_t offset){
	ERR("DEPRECATED: Should never be called");
	return -1;
}

int ust_instrument_probe_v2(struct ust_app *app,
		const char *name,
		enum lttng_ust_instrumentation instrumentation,
		uint64_t addr,
		const char *symbol,
		uint64_t offset)
{

	BPatch bpatch;
	BPatch_process *process = NULL;
	BPatch_image *image;
	/* Instrumentation points of probe callback function */
	std::vector<BPatch_point *> *points;
	std::vector<BPatch_function *> functions;
	int ret;
	if (check_dyninst_rt_lib()) {
		ERR("Can not find dyninst RT library");
		goto error;
	}
	DBG("------avant Attach");
	process = bpatch.processAttach(NULL, app->pid);
	DBG("------apres Attach");
	if (!process) {
		ERR("Can not attach process %d", app->pid);
		goto error;
	}
	DBG("a");
	image = process->getImage();

		DBG("a1 %s", symbol);
//	object = find_match_object(image, object_path);
//	if (!object) {
//		ERR("Can not find object %s in process %d", object_path, app->pid);
//		goto error;
//	}

	switch (instrumentation) {
	case LTTNG_UST_FUNCTION:
		image->findFunction(symbol, functions, false);

		if (functions.size() == 0) {
			ERR("No functions %s found in app process", symbol);
			goto error;
		}
		if (functions.size() > 1) {
			ERR("Multiple instances of %s found in app process", symbol);
			goto error;
		}

	//	ret = instrument_process_tracef(process, image, *points, functions[0]);
		ret = instrument_function_entry(process, symbol, name, true);
		DBG("b");
	//	ret = instrument_function_entry(process, symbol, name, false);
//		DBG("---Instrument entry avant");
//		ret = instrument_process(process, image, *points,
//				tracepoint->u.function.entry);
//		DBG("---Instrument entry apres");
		if (ret) {
			goto error;
		}

		//ret = instrument_function_exit(process, symbol, name);
	//	ret = instrument_process(process, image, *points,
	//		tracepoint->u.function.exit);
		if (ret) {
			goto error;
		}
		break;
	case LTTNG_UST_PROBE:
		image->findFunction(symbol, functions, false);

		if (functions.size() == 0) {
			ERR("No functions %s found in app process", symbol);
			goto error;
		}
		if (functions.size() > 1) {
			ERR("Multiple instances of %s found in app process", symbol);
			goto error;
		}
		/* Instrument the entry of the function */
		points = functions[0]->findPoint(BPatch_entry);
	//	ret = instrument_process(process, image, *points,
	//			tracepoint->u.probe);
		if (ret) {
			goto error;
		}

		break;
	default:
		goto error;
		break;
	}

	goto end;

error:
	ERR("Instrument process %d failed", app->pid);
	ret = -1;

end:
	if (process) {
		process->detach(true);
	}
	return ret;
}
