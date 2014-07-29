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

#define MAX_STR_LEN 30

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
	return 0;
}
int create_tracepoint(BPatch_variableExpr *tp, BPatch_variableExpr * signature, BPatch_variableExpr *name )
{
	struct tracepoint t = {
		.name = (const char*) name->getBaseAddr(), //Does this work?
		.state = 0,
		.probes = NULL,
		.tracepoint_provider_ref = NULL,
		.signature = (const char*) signature->getBaseAddr(),//Does this work?
	};

	tp->writeValue((void *) &t, sizeof(struct tracepoint), false);
	return 0;
}

int create_event_field_array(BPatch_process *process,int nb_field,
		struct lttng_event_di_field *event_fields, BPatch_variableExpr *event_descArrayExpr,
		BPatch_variableExpr *name, BPatch_variableExpr *signature, unsigned long *addr)
{
	BPatch_image *image = process->getImage();

	BPatch_variableExpr *event_fieldsExpr;
	struct lttng_event_field * fields;
	if(nb_field > 0)
	{

		event_fieldsExpr = process->malloc(sizeof(struct lttng_event_field) * nb_field);
		event_fieldsExpr->writeValue(event_fields, sizeof(struct lttng_event_field) * nb_field, false);
		fields  = (struct lttng_event_field *)  event_fieldsExpr->getBaseAddr();
	}
	else
	{
		/*
		 * Event_fields should be null because the number of field is zero
		 */
		assert(event_fields == NULL);
		event_fieldsExpr = process->malloc(sizeof(long long));
		/*
		 * We want NULL written since there is no field in the tracepoint
		 */
		int allo = 0;
		event_fieldsExpr->writeValue(&allo, sizeof(void *), false);
		nb_field = 0;
		fields = NULL;
	}

	/*
	 * Create event description, this description must be add to an array for the registration
	 * So we have to allocate an array of event description in the mutatee.
	 */

	struct lttng_event_desc event_desc = {
		.name = (const char*) name->getBaseAddr(),
		.probe_callback = (void (*)()) 1337, //FIXME: must set the probe callback to none null value but is not used
		.ctx = NULL,
		.fields = (const struct lttng_event_field *) fields,
		.nr_fields = (unsigned int) nb_field,
		.loglevel = NULL,
		.signature = (const char*) signature->getBaseAddr(),
	};

	DBG("c1");
	BPatch_variableExpr *event_descExpr = process->malloc(sizeof(struct lttng_event_desc));
	event_descExpr->writeValue(&event_desc, sizeof(struct lttng_event_desc), false);

	*addr = (unsigned long) event_descExpr->getBaseAddr();

	return 0;
}

int instrument_function(BPatch_process *process,
			const char *symbol, const char *event_name)
{

	DBG("Instrumenting function \"%s\"", symbol);
	process->loadLibrary("/home/frdeso/projets/runtime-ust/tp.so");
	process->loadLibrary("/usr/local/lib/liblttng-ust.so");

	BPatch_variableExpr *name_entry_expr = process->malloc(sizeof(char) * MAX_STR_LEN);
	BPatch_variableExpr *name_exit_expr = process->malloc(sizeof(char) * MAX_STR_LEN);
	BPatch_variableExpr *sign_entry_expr = process->malloc(sizeof(char) * MAX_STR_LEN);
	BPatch_variableExpr *sign_exit_expr = process->malloc(sizeof(char) * MAX_STR_LEN);
	BPatch_variableExpr *prov_expr = process->malloc(sizeof(char) * MAX_STR_LEN);

	/*
	 * Format the name, signature and provider of the event
	 */
	char *name_entry_arr = (char *) malloc(sizeof(char) * MAX_STR_LEN);
	char *name_exit_arr = (char *) malloc(sizeof(char) * MAX_STR_LEN);
	char *prov_arr = (char *) malloc(sizeof(char) * MAX_STR_LEN);

	char *sign_entry_arr;
	char *sign_exit_arr;

	sprintf(name_entry_arr,"%s_entry", event_name);
	sprintf(name_exit_arr,"%s_exit", event_name);

	sign_entry_arr = strchr(name_entry_arr,':');
	if(sign_entry_arr == NULL)
	{
		return -1;
	}
	sign_entry_arr +=1;

	sign_exit_arr = strchr(name_exit_arr,':');
	if(sign_exit_arr == NULL)
	{
		return -1;
	}
	sign_exit_arr +=1;

	strncpy(prov_arr, name_entry_arr, MAX_STR_LEN);
	char *prov_delimiter = strchr(prov_arr, ':');
	prov_delimiter[0] = '\0';

	name_entry_expr->writeValue((char *) name_entry_arr, MAX_STR_LEN, false);
	name_exit_expr->writeValue((char *) name_exit_arr, MAX_STR_LEN, false);
	sign_entry_expr->writeValue((char *) sign_entry_arr, MAX_STR_LEN, false);
	sign_exit_expr->writeValue((char *) sign_exit_arr, MAX_STR_LEN, false);
	prov_expr->writeValue((char *) prov_arr, MAX_STR_LEN, false);

	/*
	 * Free char arrays
	 */
	free(name_entry_arr);
	free(name_exit_arr);
	free(prov_arr);

	/*
	 * Create a tracepoint structure and copy it in the
	 * mutatee address space.
	 */
	BPatch_variableExpr *tp_entry_expr = process->malloc(sizeof(struct tracepoint));
	BPatch_variableExpr *tp_exit_expr = process->malloc(sizeof(struct tracepoint));
	create_tracepoint(tp_entry_expr, sign_entry_expr, name_entry_expr);
	create_tracepoint(tp_exit_expr, sign_exit_expr, name_exit_expr);
	/*
	 *Call the tracepoint_register function rightaway
	 */
	vector<BPatch_snippet *> *register_call_sequence =  new vector<BPatch_snippet*>();
	register_tp_from_mutatee(process, tp_entry_expr, register_call_sequence);
	register_tp_from_mutatee(process, tp_exit_expr, register_call_sequence);

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
	struct lttng_event_di_field *event_entry_fields, *event_exit_fields;
	int nb_field = params->size();

	if(nb_field > 0)
	{
		event_entry_fields = (struct lttng_event_di_field* ) malloc(sizeof(struct lttng_event_di_field)*nb_field);
		if(event_entry_fields == NULL)
		{
			return -1;
		}
	}
	else
	{
		event_entry_fields = NULL;
	}

	event_exit_fields = NULL;



	int __event_len = 0;
	for(int i = 0;i < nb_field ; ++i)
	{
		BPatch_variableExpr* field_name_expr = process->malloc(sizeof(char) * MAX_STR_LEN);
		field_name_expr->writeValue((char *)(*params)[i]->getName(), MAX_STR_LEN);

		// Add a field depending on the type of the parameter
		switch((*params)[i]->getType()->getDataClass())
		{
		case BPatch_dataScalar:
		{
			string typeName = (*params)[i]->getType()->getName();
			if(typeName == "char")
			{
				add_char_event_field(&event_entry_fields[i],
						(char *) field_name_expr->getBaseAddr());
				__event_len
					+= (lib_ring_buffer_align(__event_len, lttng_alignof(char))
					+ sizeof(char));
				image->findFunction("event_write_char", field_fcts);
#warning "might fail"
			}
			else
			{
				add_int_event_field(&event_entry_fields[i],(char *) field_name_expr->getBaseAddr());
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
	DBG("b");
	unsigned long addr[2];
	BPatch_variableExpr *event_descArrayExpr =
		process->malloc(sizeof(struct lttng_event_desc*) * 2); //2 events. Entry and exit
	DBG("b1");
	create_event_field_array(process, params->size(), event_entry_fields,
			event_descArrayExpr, name_entry_expr, sign_entry_expr, &(addr[0]));
	DBG("b2");
	create_event_field_array(process, 0, event_exit_fields,
			event_descArrayExpr, name_exit_expr, sign_exit_expr, &(addr[1]));

	DBG("b3");
	event_descArrayExpr->writeValue(addr,  sizeof(struct lttng_event_desc*) * 2, false);

	DBG("c");
	/*
	 * Create probe description and register it.
	 */
	struct lttng_probe_desc desc = {
		.provider = (const char*) prov_expr->getBaseAddr(),
		.event_desc = (const struct lttng_event_desc **) event_descArrayExpr->getBaseAddr(),
		.nr_events = 2,
		.head = { NULL, NULL },
		.lazy_init_head = { NULL, NULL },
		.lazy = 0,
		.major = LTTNG_UST_PROVIDER_MAJOR,
		.minor = LTTNG_UST_PROVIDER_MINOR,
		.type = LTTNG_PROBE_INSTRUMENT,
	};

	DBG("d");
	BPatch_variableExpr *probe_descExpr = process->malloc(sizeof(struct lttng_probe_desc));
	probe_descExpr->writeValue(&desc, sizeof(struct lttng_probe_desc), false);

	probe_register_from_mutatee(process, probe_descExpr, register_call_sequence);

	BPatch_variableExpr *isRegistered = process->malloc(*(image->findType("int")));
	complete_registration(process, register_call_sequence, isRegistered);
	/*
	 * We are now ready to insert the tracepoint in the running binary.
	 * This is done in three step.
	 * 	1. Allocate and initialize the context in the mutatee
	 * 	2. Register one call expression for each paramaters
	 * 	3. Commit the event
	 */

	vector<BPatch_snippet *> args;
	vector<BPatch_function *> init_ctx_fct, commit_fct;
	vector<BPatch_snippet *> call_entry_seq, call_exit_seq;

	/*
	 * Allocate context
	 */

	BPatch_variableExpr *ctx_entry_expr = process->malloc(sizeof(struct lttng_ust_lib_ring_buffer_ctx));
	BPatch_variableExpr *ctx_exit_expr = process->malloc(sizeof(struct lttng_ust_lib_ring_buffer_ctx));

	/*
	 * Initializing context
	 */
	image->findFunction("init_ctx", init_ctx_fct);
	if(init_ctx_fct.size() != 1)
	{
		ERR("Function init_ctx not found.")
		return -1;
	}
	
	args.push_back(new BPatch_constExpr(ctx_entry_expr->getBaseAddr()));
	args.push_back(new BPatch_constExpr(tp_entry_expr->getBaseAddr()));
	args.push_back(new BPatch_constExpr( __event_len ));
	args.push_back(isRegistered);
	BPatch_funcCallExpr init_ctx_entry_fct_call(*(init_ctx_fct[0]), args);
	call_entry_seq.push_back(&init_ctx_entry_fct_call);

	args.clear();

	args.push_back(new BPatch_constExpr(ctx_exit_expr->getBaseAddr()));
	args.push_back(new BPatch_constExpr(tp_exit_expr->getBaseAddr()));
	args.push_back(new BPatch_constExpr( 0 ));
	args.push_back(isRegistered);
	BPatch_funcCallExpr init_ctx_exit_fct_call(*(init_ctx_fct[0]), args);
	call_exit_seq.push_back(&init_ctx_exit_fct_call);

	args.clear();
	/*
	 * Add call expression for each parameter
	 */
	for(int i = 0 ; i < nb_field ; ++i)
	{
		args.push_back(new BPatch_constExpr(ctx_entry_expr->getBaseAddr()));
		args.push_back(new BPatch_constExpr(tp_entry_expr->getBaseAddr()));
		args.push_back(new BPatch_constExpr( __event_len ));
		args.push_back(new BPatch_paramExpr(i));
		args.push_back(isRegistered);
		BPatch_funcCallExpr *field_call = new BPatch_funcCallExpr(*(field_fcts[i]), args);
		call_entry_seq.push_back(field_call);

		args.clear();
	}

	/*
	 * Commit the event
	 */

	image->findFunction("event_commit", commit_fct);
	if(commit_fct.size() != 1)
	{
		ERR("Function event_commit not found.")
		return -1;
	}

	vector<BPatch_point *>* insert_points;

	args.push_back(new BPatch_constExpr(ctx_entry_expr->getBaseAddr()));
	args.push_back(new BPatch_constExpr(tp_entry_expr->getBaseAddr()));
	args.push_back(isRegistered);
	BPatch_funcCallExpr event_commit_entry_call(*(commit_fct[0]), args);
	call_entry_seq.push_back(&event_commit_entry_call);

	insert_points = function->findPoint(BPatch_entry);
	process->insertSnippet(BPatch_sequence(call_entry_seq), *(*insert_points)[0]);


	args.clear();
	args.push_back(new BPatch_constExpr(ctx_exit_expr->getBaseAddr()));
	args.push_back(new BPatch_constExpr(tp_exit_expr->getBaseAddr()));
	args.push_back(isRegistered);
	BPatch_funcCallExpr event_commit_exit_call(*(commit_fct[0]), args);
	call_exit_seq.push_back(&event_commit_exit_call);

	insert_points = function->findPoint(BPatch_exit);
	process->insertSnippet(BPatch_sequence(call_exit_seq), *(*insert_points)[0]);

	args.clear();
	field_fcts.clear();

	return 0;
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
	process = bpatch.processAttach(NULL, app->pid);
	if (!process) {
		ERR("Can not attach process %d", app->pid);
		goto error;
	}
	image = process->getImage();

	switch (instrumentation) {
	case LTTNG_UST_FUNCTION:
		
		ret = instrument_function(process, symbol, name);
		if (ret) {
			goto error;
		}
		break;
	case LTTNG_UST_PROBE:
		/* Instrument the entry of the function */

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
