Fallen tree-bridge
==================

Tool and API for interconnecting digital forensic treegraph modules with digital forensic framework implementations.


Fallen tree bridge API
======================

The fallen-tree-bridge API is a forensic treegraph decomposition API inspired by the Open Computer Forensics Architecture (OCFA) treegraph API.
While OCFA is an architecture aimed primaraly at relatively large scale computer forensic investigations, and while OCFA aimed primarily at 
'deep and extensive' analysis, computer forensic investigations occure in a wide scale of settings ranging from triage to deep and extensive 
and ranging from a single thumbdrive to thousands of disk images adding up to tens or even hundreds of peta bytes. Given this, its unlikley 
that a single computer forensics framework could ever be deviced to address this full spectrum.
 
With the fallen-tree-bridge API we try to address the idea that the concept of a tree-graph API for forensic frameworks could be the universal 
binding factor for computer forensic frameworks no matter what part of the spectrum they address. 

The fallen-tree-bridge project attempts to define interfaces that allow computer forensics 'module' developers to create framework-agnostic 
tree-graph modules. 

With a wide range of possible computer forensic treegraph modules for addressing different kinds of data, and with a wide range of possible 
computer forensic frameworks for addressing different scale end intensity levels, the fallen-tree-bridge project arives at the concept
of 'framework as a module'. That is, both fallen-tree-bridge compatible treegraph modules and fallen-tree-bridge compatible framework connectors
are implemented as runtime loadable shared libraries.

FTB treegraph modules
=====================

More info will follow.

Header only approach for frameworks
===================================

More info will follow.


Embedding approach for frameworks
=================================

More info will follow.


