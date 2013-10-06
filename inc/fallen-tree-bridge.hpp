#ifndef _FALLEN_TREE_BRIDGE_HPP_
#define _FALLEN_TREE_BRIDGE_HPP__
#if __cplusplus < 201103L
#error This library needs a C++11 compliant compiler
#endif
#include <string>
#include <time.h>
#include <sys/types.h>
#include <functional>
//This file contains the C++(11) version of the Fallen-Tree-Bridge forensic unified treegraph interface API.
//This API is meant to be a forensic-framework-neutral C++ API for decoupling forensic treegraph modules
//from forensic treegraph frameworks.
//
//A forensic-treegraph module must be built as a shared library named "libftb_${modulename}.so" that 
//must implement an "extern C" zero argument function named "ftb_${modulname}_constructor" that
//returns a pointer to newly allocated concrete subclass of ftb::AbstractModule.
//
//A forensic framework must provide a shared library named "libftbframework_${frameworkname}.so" that must 
//implement an "extern C" zero argument function named "ftbframework_constructor" that 
//returns a pointer to newly allocated concrete subclass of ftb::AbstractFramework.
//
//A tool named 'ftb-bind' should be available to bind a framework implementation to one or more modules.
//
//To clarify with a concrete example, lets assume we have a framework called 'mattock' that uses one process per module 
//and we have two modules, one named 'sleuthkit-filesystem' and one called 'magic'. This would mean we have 3 libraries:
//
//  * libftbframework_mattock.so that implements:
//     + ftb::AbstractFramework *ftbframework_constructor();
//  * libftbmodule_sleuthkit-filesystem.so that implements:
//     + ftb::AbstractModule *ftbmodule_sleuthkit-filesystem_constructor();
//  * libftbmodule_magic.so that implements:
//     + ftb::AbstractModule *ftbmodule_magic_constructor();
//
//Now to start the modules within the context of the chosen framework, the following commands may be given:
//
//  ftb-bind --ftb-framework=mattock --ftb-modules=magic --mattock-mode=module
//  ftb-bind --ftb-framework=mattock --ftb-modules=sleuthkit-filesystem --mattock-mode=kickstart --mattock-kickstartfile=Foo.dd
//
//Lets take the second invocation as example of how ftb-bind shall bind the framework to the module.
//The tool will take the arguments "--ftb-framework=mattock" and "--ftb-modules=sleuthkit-filesystem" and
//determine it should dynamically load those libraries and invoke their constructor. The ftb-bind tool invokes both constructors, 
//ending up with a pointer to a ftb::AbstractFramework and a pointer to (in this example) one ftb::AbstractModule. 
//It will than invoke the 'registerModule' method of the ftb::AbstractFramework with each (in this case only one) ftb::AbstractModule 
//it has acquired.
//Finaly, the ftb::AbstractFramework is invoked using the remaining command line arguments.
//
//This setup should allow independent development of forensic treegraph based frameworks and 

namespace ftb {
  //Helper interface class that casts either to an input stream or a local filepath or allows reading with random access. 
  class AbstractParentData {
    public:
      virtual off_t size()=0; //The full size of the entity.
      virtual operator std::istream &()=0; //Get as a C++ input stream. 
      virtual operator std::string()=0; //Get the local path for calling 3th party libs or tools. 
                                        //Using the path rather than the istream may incur additional 
                                        //overhead in a distributed system. 
      virtual ssize_t read(off_t offset,void *buf, size_t count)=0; //Random access to a piece of data. 
                                                                  //Using random access rather than sequential
                                                                  //may incur additional overhead in a distributed system.
      virtual std::string sha1()=0;
      virtual ~AbstractParentData(){}
  };
  //The interface for setting meta-data for the node.
  class AbstractNodeMeta;
  class AbstractNodeMeta {
    public:
      //Helper class so we can write stuff like : metadata["answer"]=42;
      //Note that this is just syntactic sugar as one can always call metadata.setMeta("answer",42) instead. 
      class MetaKey;
      class MetaKey {
          std::string mKey;
          AbstractNodeMeta *mMetastream;
        public:
          MetaKey(std::string key,AbstractNodeMeta *metastream):mKey(key),mMetastream(metastream){}
          MetaKey& operator =(std::string val) {
              mMetastream->setMeta(mKey,val,"UTF8");
              return *this;
          }
          MetaKey& operator =(long double val) {
              mMetastream->setMeta(mKey,val);
              return *this;
          }
          MetaKey& operator =(long long val) {
              mMetastream->setMeta(mKey,val);
              return *this;
          }
          MetaKey& operator =(int val) {
              mMetastream->setMeta(mKey,static_cast<long long>(val));
              return *this;
          }
      };
      //Set a meta value is defined for several basic types for the value. Module builders should NOT invoke setMeta directly
      //but should instead make use of the operator[] based interface.
      virtual void setMeta(std::string key,std::string val,std::string encoding="UTF8")=0; //String meta-data, optionally 
                                                                                           //encoded differently than the default UTF8
      virtual void setMeta(std::string key,long double val)=0; //float meta-data.
      virtual void setMeta(std::string key,long long val)=0;//Integer meta-data.
      virtual void setMeta(std::string key,time_t val,std::string timesourceref)=0;//Time meta-data. A timesource identifies time values 
                                                                                   //that should be assumed to have the same callibration.
      virtual void setMeta(std::string key,time_t val)=0;//Time meta-data, Use a unique parent data id as time source.
      //Convenience converter to avoid problems with literals
      void setMeta(std::string key,int val){ this->setMeta(key,static_cast<long long>(val));}
      //Convenience [] operator so we can write stuff like : metadata["answer"]=42;
      MetaKey operator[](std::string key) {
         return MetaKey(key,this);
      }
      virtual ~AbstractNodeMeta(){}      
  };

  class AbstractSubnodeProcessor;

  //This typedef defines a function object or lambda footprint for sub node's in the tree graph. 
  //The function when invoked should supply the framework with data, meta-data and its direct child node's. 
  //To allow the implementation of the function to do this, the following arguments are provided on invocation:
  //  * addDerivedContent : Add a chunk of data that can not be designated as a chunk of parent data.
  //  * addParentFragment : Add a chunk of the parent as being part of the child node data.
  //  * addSparseFragment : Add a sparse section of a given size to the child node.
  //  * metadata : An operatop overloaded object for adding meta-data.
  //  * processChild : A functor that allows a node function to register its child nodes for inmediate or delayed processing.

  typedef std::function<void(std::function<void(const char *buf, size_t count)> &addDerivedContent,
                               std::function<void(off_t offset, off_t size)> &addParentFragment,
                               std::function<void(off_t size)> &addSparseFragment,
                               AbstractNodeMeta &metadata,
                               AbstractSubnodeProcessor &processChild) const> childnode_functor;

  //This function object allows the registering of a named child node. Its arguments are the node name and a node function.
  class AbstractSubnodeProcessor {
    public:
      virtual void operator()(std::string childname, childnode_functor &subnode)=0;
      virtual ~AbstractSubnodeProcessor(){}
  };

  //The base interface for ftb modules. 
  //The AbstractModule functor has 5 arguments:
  //  * parentData : Interface to the content of the parent node.
  //  * parentMetaData : An operator overloaded object for adding meta-data. This is a write only interface to parent meta-data.
  //                     Experience with OCFA has shown that hashes has shown that generic modules don't require read access
  //                     to meta-data.  
  //  * getWorkdir : Functor that allows asking for a working directory path of a given prommised max size. Depending on the
  //                 size asked for and system configuration this functor may return either a regular directory path or a
  //                 path to a ramdisk based directory.
  //  * processChild : A functor that allows a node function to register its child nodes for inmediate or delayed processing. 
  //
  class AbstractModule {
    public:
      virtual void operator()(AbstractParentData &parentData,
                              AbstractNodeMeta &parentMetaData,
                              std::function<std::string(off_t )> &getWorkdir,
                              AbstractSubnodeProcessor &processChild)=0;
      virtual ~AbstractModule(){}
  };

  //The base interface for ftb aware frameworks. 
  //Prior to invoking the AbstractFramework, modules should first be registered with the framework.
  class AbstractFramework;
  class AbstractFramework {
     public:
     //Helper class for the operator[] based assignments.
     class ModulesKey {
         std::string mKey;
         AbstractFramework *mFramework;
       public:
         ModulesKey(std::string key, AbstractFramework *fw):mKey(key),mFramework(fw){}
         ModulesKey& operator =(AbstractModule &module) {
            mFramework->registerModule(mKey,module);
            return *this;
         }        
     };
     //Method for regisering a module to the framework. 
     virtual void registerModule(std::string modname,AbstractModule &module)=0;
     virtual int operator()(int argc,char **argv)=0;
     ModulesKey operator[](std::string modname) {
         return ModulesKey(modname,this);
     }
  };
}
#endif
