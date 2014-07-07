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

extern "C" {
#include <link.h>
#include "ust-app.h"
#include "ust-instrument.h"
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

	std::vector<BPatch_snippet *> args, tmp_args;
	std::string fmt("params: ");
	vector<BPatch_localVar *> *params = function->getParams();
	if(params->size() == 0)
	{
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
		uint64_t offset)
{
	BPatch bpatch;
	BPatch_process *process = NULL;
	BPatch_image *image;
	BPatch_object *object;
	/* Instrumentation points of probe callback function */
	std::vector<BPatch_point *> *points;
	std::vector<BPatch_function *> functions;
	int ret;
	if (check_dyninst_rt_lib()) {
		ERR("Can not find dyninst RT library");
		goto error;
	}

	process = bpatch.processAttach(object_path, app->pid);
	if (!process) {
		ERR("Can not attach process %d", app->pid);
		goto error;
	}
	image = process->getImage();

	object = find_match_object(image, object_path);
	if (!object) {
		ERR("Can not find object %s in process %d", object_path, app->pid);
		goto error;
	}

	switch (instrumentation) {
	case LTTNG_UST_FUNCTION:
		object->findFunction(symbol, functions, false);

		if (functions.size() == 0) {
			ERR("No functions %s found in app process", symbol);
			goto error;
		}
		if (functions.size() > 1) {
			ERR("Multiple instances of %s found in app process", symbol);
			goto error;
		}

		points = functions[0]->findPoint(BPatch_entry);
		ret = instrument_process_tracef(process, image, *points,
				functions[0]);
		//ret = instrument_function_entry(process, image, functions[0]);
		if (ret) {
			goto error;
		}

		points = functions[0]->findPoint(BPatch_exit);
		ret = instrument_process(process, image, *points,
				tracepoint->u.function.exit);
		if (ret) {
			goto error;
		}
		break;
	case LTTNG_UST_PROBE:
		object->findFunction(symbol, functions, false);

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
		ret = instrument_process(process, image, *points,
				tracepoint->u.probe);
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
