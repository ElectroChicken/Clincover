# Clincover

Clincover is a prototype coverage testing tool for answer set programms. It uses the power of the integrated ASP system clingo to calculate five different code coverage metrics defined by [Janhunen et al.](https://doi.org/10.3233/978-1-60750-606-5-951). Two versions exist: One for propositional normal programs (clincover.py) and one that works with all types of ASP programs (clincovar.py).

## Usage
usage: clincover.py [-h] [-p] [-r] [-d] [-l] [-c] [-v] -t
                    TESTCASES [TESTCASES ...]
                    files [files ...]



positional arguments:  
&emsp;    files  &emsp;&emsp;  The program files

optional arguments:  
  -h,&emsp; --help      &emsp;&emsp;&emsp;&emsp;&emsp;      show this help message and exit  
  -p,&emsp; --program   &nbsp;&emsp;&emsp;&emsp;      check for program coverage  
  -r,&emsp;&nbsp; --rule      &emsp;&emsp;&ensp;&emsp;&emsp;&emsp;      check for rule coverage  
  -d,&emsp; --definition &emsp;&emsp;&emsp;      check for definition coverage  
  -l,&emsp;&nbsp; --loop       &emsp;&emsp;&nbsp;&emsp;&emsp;&emsp;     check for loop coverage  
  -c,&emsp; --component  &emsp;&emsp;     check for component coverage  
  -v,&emsp; --verbose    &ensp;&emsp;&emsp;&emsp;     display additional coverage
                        information like locations  
  -t TESTCASES [TESTCASES ...],&emsp; --testcases TESTCASES [TESTCASES ...]&emsp;&emsp;
                        The testcase files
