#include <BPatch.h>
#include <iostream>
#include <BPatch_function.h>
using namespace std;
#define BIN_PATH  "/home/frdeso/projets/dyninst-sandbox/suspect"
int main(int argc, char **argv)
{

	if(argc <= 1)
	{
		cout<<"No binary to examine. Exiting..."<<endl;
		exit(-1);
	}
	char *path = argv[1];
	BPatch bpatch;


	BPatch_binaryEdit *proc = bpatch.openBinary(path);
	BPatch_image *image = proc->getImage();
	vector<BPatch_function*> *fcts = image->getProcedures(false);
	fcts->clear();
	std::vector<BPatch_module *> *mods = image->getModules();
	char buff[256];
	if(mods->size() == 0){
	    cerr<<"No module found"<<endl;
	    exit(0);
	}
	cout<<"mods "<<mods->size()<<endl;

	for(BPatch_module *i: *mods)
	{
		i->getName(buff,256);
		//if(strcmp(buff,"DEFAULT_MODULE") == 0)
		{
			//cout<<"*"<<buff<<endl;
			fcts = i->getProcedures();
	    	    	if(fcts->size() == 0){
	    	    		cerr<<buff<<": No function found"<<endl;
	    	    		continue;
	    	    	}
			cout<<"fcts "<<fcts->size()<<endl;
			for(BPatch_function *j: *fcts)
			{
				vector<BPatch_localVar *> *params = j->getParams();
				cout<<"("<<buff<<") "<<j->getName()<<"(";
				for(unsigned int i = 0; i < params->size(); ++i )
				{
					//Push the type of the next argument
					switch((*params)[i]->getType()->getDataClass())
					{
					case BPatch_dataScalar:
					    cout<<(*params)[i]->getType()->getName()<<" "<<(*params)[i]->getName();
					    break;
					case BPatch_dataPointer:
					    cout<<(*params)[i]->getType()->getConstituentType()->getName()<<" *"<<(*params)[i]->getName();
					    break;
					case BPatch_dataStructure:
					    cout<<"struct "<< (*params)[i]->getName();
					    break;
					default:
					    cout<<(*params)[i]->getType()->getName()<<" " <<(*params)[i]->getName();
					    break;
					}
					if(i < params->size()-1)
						cout<<", ";
				}
				cout<<")"<<endl;
			}
			fcts->clear();
		}
	}
	return 0;
}
