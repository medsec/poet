POET
====
POET (Pipelineable On-line Encryption with authentication Tag) is an
on-line authenticated encryption scheme designed by Farzaneh Abed,
Scott Fluhrer, Scott Fluhrer, Christian Forler, Eik List, Stefan
Lucks, David McGrew, and Jakob Wenzel.


Initial CAESAR submission:
http://competitions.cr.yp.to/caesar-submissions.html


Current specification:
http://www.uni-weimar.de/de/medien/professuren/mediensicherheit/research/poet/


Content
-------
* C reference implementation of POET-AES128 (v1) with software AES
* C optimized implementation of POET-AES128 (v1) with AES-NI
* C reference implementation of POET-AES4 (v1) with software AES
* C optimized implementation of POET-AES4 (v1) with AES-NI
* C reference implementation of POET-AES128 (v2) with software AES, 
  without intermediate tags (ls = 0, lt = 0)
* C optimized implementation of POET-AES128 (v2) with AES-NI, 
  without intermediate tags (ls = 0, lt = 0)
* C reference implementation of POET-AES128 (v2) with software AES, 
  with intermediate tags (ls = 128, lt = 128)
* C reference implementation of POET-AES4 (v2) with software AES, 
  without intermediate tags (ls = 0, lt = 0)
* C optimized implementation of POET-AES4 (v2) with AES-NI, 
  without intermediate tags (ls = 0, lt = 0)
* C reference implementation of POET-AES4 (v2) with software AES, 
  with intermediate tags (ls = 128, lt = 128)

ls denotes the number of blocks between subsequent intermediate tags.
lt the length in bits of intermediate tags.

Dependencies
------------
* clang   (http://clang.llvm.org/)
* make    (http://www.gnu.org/software/make/)
