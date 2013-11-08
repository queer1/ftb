#include "../inc/fallen-tree-bridge.hpp"
#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include <boost/lexical_cast.hpp>

class DemoParentData: public ftb::AbstractParentData {
    std::ifstream mFileStream;
    off_t mSize;
    std::string mHash;
  public:
    DemoParentData(std::string filename):mFileStream(filename),mSize(0),mHash(""){

    }
    off_t size() {
        return mSize;
    }
    operator std::istream &() {
       return mFileStream;
    }
    operator std::string() {
       return "";
    }
    ssize_t read(off_t offset,void *buf, size_t count) {
       return 0;
    }
    std::string sha1(){
       if (mHash == "") {
          mHash="da39a3ee5e6b4b0d3255bfef95601890afd80709";
       }
       return mHash;
    }
};

class DemoParentMeta: public ftb::AbstractNodeMeta {
  public:
   void setMeta(std::string key,std::string val,std::string encoding) {
      std::cout << "\t" << key << "\t=\t" << val << std::endl;
   }
   void setMeta(std::string key,long double val) {
      this->setMeta(key,boost::lexical_cast<std::string>(val),"UTF8");
   }
   void setMeta(std::string key,long long val) {
      this->setMeta(key,boost::lexical_cast<std::string>(val),"UTF8");
   }
   void setMeta(std::string key,time_t val,std::string timesourceref) {
      this->setMeta(key,timesourceref + "::" + boost::lexical_cast<std::string>(val),"UTF8");
   }
   void setMeta(std::string key,time_t val) {
      this->setMeta(key,boost::lexical_cast<std::string>(val),"UTF8");
   }   
};

class IgnoreSubNode: public ftb::AbstractSubnodeProcessor {
  public:
    void operator()(std::string childname, ftb::childnode_functor &subnode) {
      std::cout << "Ignoring subnode: " << childname << std::endl;
    }    
};

std::string wd(off_t maxdata) {
  return "/tmp";
}

class DemoFramework: public ftb::AbstractFramework {
    std::map<std::string,ftb::AbstractModule &> mModules;
  public:
    void registerModule(std::string modname,ftb::AbstractModule &module){
       mModules.insert(std::pair<std::string,ftb::AbstractModule &>(modname,module) );
    }
    int operator()(int argc,char **argv) {
       for (auto& kv : mModules) {
          if (kv.first == "demomodule") {
            DemoParentData pd(argv[1]);
            DemoParentMeta pm;
            std::function<std::string(off_t)> wd = [](off_t) { return "/tmp";};
            IgnoreSubNode snp;
            kv.second(pd,pm,wd,snp);  
          }
       }
       return 0;
    }
};

extern "C" {
  ftb::AbstractFramework *ftbframework_constructor() {
     return new DemoFramework;
  }
}
