

Ok, so there may be actually a bug, since in the cleanup step we are calling index 0 function which may not be the function to clean up:

                             *************************************************************
                             *  const Mso::SVG::SVGImage::`vftable'{for `Mso::TRefCount   .
                             *************************************************************
                             ??_7SVGImage@SVG@Mso@@6B?$TRefCountedImpl@UISV  XREF[7]:     SVGImage:180003443 (*) , 
                             Mso::SVG::SVGImage::`vftable'{for_`Mso::TRefCo               SVGImage:18000344a (*) , 
                                                                                          SVGImage:180003542 (*) , 
                                                                                          SVGImage:180003549 (*) , 
                                                                                          Clone:18000473f (*) , 
                                                                                          Clone:180004746 (*) , 
                                                                                          Clone:180004762 (R)   
       18014b4b0 40  74  00       addr       Mso::TRefCountedImpl<>::AddRef
                 80  01  00 
                 00  00
       18014b4b8 10  74  00       addr       Mso::TRefCountedImpl<>::Release
                 80  01  00 
                 00  00
       18014b4c0 70  50  00       addr       Mso::SVG::SVGImage::GetIStream
                 80  01  00 
                 00  00


it may be that addref function and we should actually call at index 1



This may actually be why our fuzzer seems to hit a wall:


                    WinAFL 1.17 based on AFL 2.43b (100000)

+- process timing -------------------------------------+- overall results ----+
|        run time : 0 days, 0 hrs, 25 min, 17 sec      |  cycles done : 1     |
|   last new path : 0 days, 0 hrs, 18 min, 21 sec      |  total paths : 996   |
| last uniq crash : none seen yet                      | uniq crashes : 0     |
|  last uniq hang : none seen yet                      |   uniq hangs : 0     |
+- cycle progress --------------------+- map coverage -+----------------------+
|  now processing : 588* (59.04%)     |    map density : 1.56% / 30.52%       |
| paths timed out : 0 (0.00%)         | count coverage : 2.58 bits/tuple      |
+- stage progress --------------------+ findings in depth --------------------+
|  now trying : havoc                 | favored paths : 101 (10.14%)          |
| stage execs : 75/76 (98.68%)        |  new edges on : 374 (37.55%)          |
| total execs : 140k                  | total crashes : 0 (0 unique)          |
|  exec speed : 134.9/sec             |  total tmouts : 0 (0 unique)          |
+- fuzzing strategy yields -----------+---------------+- path geometry -------+
|   bit flips : n/a, n/a, n/a                         |    levels : 2         |
|  byte flips : n/a, n/a, n/a                         |   pending : 735       |
| arithmetics : n/a, n/a, n/a                         |  pend fav : 0         |
|  known ints : n/a, n/a, n/a                         | own finds : 238       |
|  dictionary : n/a, n/a, n/a                         |  imported : n/a       |
|       havoc : 23/19.6k, 5/72.2k                     | stability : 13.38%    |
|        trim : n/a, n/a                              +-----------------------+
+-----------------------------------------------------+   [cpu000001:   0%]



