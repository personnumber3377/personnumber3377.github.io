
# Fuzzing speedcrunch.

Speedcrunch is a scientific calculator app. https://bitbucket.org/heldercorreia/speedcrunch/src/master/

I noticed that there were tests (https://bitbucket.org/heldercorreia/speedcrunch/src/master/src/tests/) , but there wasn't a fuzzing tester for this program, so I decided to fuzz speedcrunch in order to find some problems with it.

# Compiling speedcrunch.

Now compiling speedcrunch turned out to be quite a challenge, since building it required qt 15 and I am using an os which uses qt 12 by default so I actually had to compile qt from source in order to then compile speedcrunch.

After compiling speedcrunch normally I then compiled it with afl-clang-fast as usual when fuzzing.

```

#!/bin/sh
export Qt5Help_DIR=/home/cyberhacker/Asioita/Hakkerointi/Fuzzing/speedcrunch/qt/qt5-build/qtbase/lib/cmake/Qt5Help
export CMAKE_PREFIX_PATH=/home/cyberhacker/Asioita/Hakkerointi/Fuzzing/speedcrunch/qt/qt5-build/qtbase/

CC=afl-clang-fast CXX=afl-clang-fast++ cmake -D CMAKE_C_COMPILER=afl-clang-fast -D CMAKE_CXX_COMPILER=afl-clang-fast++ -D CMAKE_C_FLAGS="-fsanitize=address,undefined" -D CMAKE_CXX_FLAGS="-fsanitize=address,undefined" ../src/ -DPORTABLE_SPEEDCRUNCH=on
#/home/cyberhacker/Asioita/Hakkerointi/Fuzzing/speedcrunch/qt/stuff/qt5-build/qtbase/lib/cmake/Qt5Help

```

Before compiling, I decided to add a target called "fuzzer" inside the tests directory:

I first copied the testevaluator.cpp file and then removed all of the tests from it. This became my fuzzer harness basically. I am going to walk you through how I implemented it.

First there is the CHECK_EVAL macro, which basically takes an expression and then looks at what the result should be, instead of using it, I am going to implement another macro called "EVAL" which, as the name implies, tries to evaluate the expression passed to it.



```
#define EVAL(x) tryEval(__FILE__,__LINE__,#x,x,y)

// ...



static void tryEval(const char* file, int line, const char* msg, const QString& expr,
                      int issue = 0, bool shouldFail = false, bool format = false)
{
    //++eval_total_tests;

    eval->setExpression(expr);
    //Quantity rn = eval->evalUpdateAns();
    Quantity rn = eval->eval(); // Do not update the "ANS" variable, because then we have absolutely no idea what the crash was if it had the "ANS" variable in it.
    
    /*
    if (!eval->error().isEmpty()) {
        if (!shouldFail) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tError: " << qPrintable(eval->error()) << endl;
        }
    } else {
        QString result = (format ? NumberFormatter::format(rn) : DMath::format(rn, Format::Fixed()));
        result.replace(QString::fromUtf8("−"), "-");
        if (shouldFail || result != expected) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tResult   : " << result.toLatin1().constData() << endl
                 << "\tExpected : " << (shouldFail ? "should fail" : expected) << endl;
        }
    }
    */

}




```

As you can see, the tryEval function is basically just setExpression() and then eval. 

# Collecting the corpus

Collecting a usable corpus is actually quite easy. there is the testevaluator file and we can just copy all of the expressions from that by using a simply python script.

```


import sys

def get_lines():
	return sys.stdin.read().split("\n")

def main() -> int:

	input_lines = get_lines()
	expressions = []
	for line in input_lines:
		# Check if the line has a test case.
		if "CHECK_EVAL(\"" in line:
			after_check_eval = line[line.index("CHECK_EVAL(\"")+len("CHECK_EVAL(\""):] # stuff that is after the check eval shit
			end_index = after_check_eval.index("\"")
			expression = after_check_eval[:end_index]
			print(expression)
			expressions.append(expression)
	count = 0
	for expr in expressions:
		fh = open("out/"+str(count), "w");
		fh.write(expr)
		fh.close()
		count += 1




	return 0

if __name__=="__main__":
	exit(main())



```

and this gets us quite a nice corpus. Now our fuzzing harness looks like this:

```

// This file is part of the SpeedCrunch project
// Copyright (C) 2004-2006 Ariya Hidayat <ariya@kde.org>
// Copyright (C) 2007-2009, 2013, 2016 @heldercorreia
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to
// the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA 02110-1301, USA.

#include "core/evaluator.h"
#include "core/settings.h"
#include "core/numberformatter.h"
#include "tests/testcommon.h"

#include <QtCore/QCoreApplication>

#include <string>
#include <iostream>
#include <unistd.h>

using namespace std;

typedef Quantity::Format Format;

static Evaluator* eval = 0;
static int eval_total_tests = 0;
static int eval_failed_tests = 0;
static int eval_new_failed_tests = 0;

#define CHECK_AUTOFIX(s,p) checkAutoFix(__FILE__,__LINE__,#s,s,p)
#define CHECK_DIV_BY_ZERO(s) checkDivisionByZero(__FILE__,__LINE__,#s,s)
#define CHECK_EVAL(x,y) checkEval(__FILE__,__LINE__,#x,x,y)
#define EVAL(x) tryEval(__FILE__,__LINE__,#x,x)
#define CHECK_EVAL_FORMAT(x,y) checkEval(__FILE__,__LINE__,#x,x,y,0,false,true)
#define CHECK_EVAL_KNOWN_ISSUE(x,y,n) checkEval(__FILE__,__LINE__,#x,x,y,n)
#define CHECK_EVAL_PRECISE(x,y) checkEvalPrecise(__FILE__,__LINE__,#x,x,y)
#define CHECK_EVAL_FAIL(x) checkEval(__FILE__,__LINE__,#x,x,"",0,true)
#define CHECK_EVAL_FORMAT_FAIL(x) checkEval(__FILE__,__LINE__,#x,x,"",0,true,true)
#define CHECK_USERFUNC_SET(x) checkEval(__FILE__,__LINE__,#x,x,"NaN")
#define CHECK_USERFUNC_SET_FAIL(x) checkEval(__FILE__,__LINE__,#x,x,"",0,true)

static void checkAutoFix(const char* file, int line, const char* msg, const char* expr, const char* fixed)
{
    ++eval_total_tests;

    string r = eval->autoFix(QString(expr)).toStdString();
    DisplayErrorOnMismatch(file, line, msg, r, fixed, eval_failed_tests, eval_new_failed_tests);
}

static void checkDivisionByZero(const char* file, int line, const char* msg, const QString& expr)
{
    ++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();

    if (eval->error().isEmpty()) {
        ++eval_failed_tests;
        cerr << file << "[" << line << "]\t" << msg << endl
             << "\tError: " << "division by zero not caught" << endl;
    }
}

static void checkEval(const char* file, int line, const char* msg, const QString& expr,
                      const char* expected, int issue = 0, bool shouldFail = false, bool format = false)
{
    ++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();

    if (!eval->error().isEmpty()) {
        if (!shouldFail) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tError: " << qPrintable(eval->error()) << endl;
        }
    } else {
        QString result = (format ? NumberFormatter::format(rn) : DMath::format(rn, Format::Fixed()));
        result.replace(QString::fromUtf8("−"), "-");
        if (shouldFail || result != expected) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tResult   : " << result.toLatin1().constData() << endl
                 << "\tExpected : " << (shouldFail ? "should fail" : expected) << endl;
        }
    }
}


static void tryEval(const char* file, int line, const char* msg, const QString& expr,
                      int issue = 0, bool shouldFail = false, bool format = false)
{
    //++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();
    /*
    if (!eval->error().isEmpty()) {
        if (!shouldFail) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tError: " << qPrintable(eval->error()) << endl;
        }
    } else {
        QString result = (format ? NumberFormatter::format(rn) : DMath::format(rn, Format::Fixed()));
        result.replace(QString::fromUtf8("−"), "-");
        if (shouldFail || result != expected) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tResult   : " << result.toLatin1().constData() << endl
                 << "\tExpected : " << (shouldFail ? "should fail" : expected) << endl;
        }
    }
    */

}



static void checkEvalPrecise(const char* file, int line, const char* msg, const QString& expr, const char* expected)
{
    ++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();

    // We compare up to 50 decimals, not exact number because it's often difficult
    // to represent the result as an irrational number, e.g. PI.
    string result = DMath::format(rn, Format::Fixed() + Format::Precision(50)).toStdString();
    DisplayErrorOnMismatch(file, line, msg, result, expected, eval_failed_tests, eval_new_failed_tests, 0);
}

#define FUZZ_BUF_SIZE 1000

int main(int argc, char* argv[])
{
    const char* fuzz_input[FUZZ_BUF_SIZE];
    QCoreApplication app(argc, argv);

    
    Settings* settings = Settings::instance();
    settings->angleUnit = 'r';
    settings->setRadixCharacter('.');
    settings->complexNumbers = false;
    DMath::complexMode = false;

    eval = Evaluator::instance();

    eval->initializeBuiltInVariables();
    /*
    test_constants();
    test_exponentiation();
    test_unary();
    test_binary();

    test_divide_by_zero();
    test_radix_char();

    test_thousand_sep();
    test_sexagesimal();

    test_function_basic();
    test_function_trig();
    test_function_stat();
    test_function_logic();
    test_function_discrete();
    test_function_simplified();

    test_auto_fix_parentheses();
    test_auto_fix_ans();
    test_auto_fix_trailing_equal();
    test_auto_fix_powers();
    test_auto_fix_untouch();

    test_comments();

    test_user_functions();

    test_implicit_multiplication();
    */

    settings->complexNumbers = true;
    DMath::complexMode = true;
    eval->initializeBuiltInVariables();
    /*
    test_complex();
    test_format();
    test_datetime();

    test_angle_mode(settings);
    */

    // Now here is the actual main fuzzer entry point:

    // First set everything to null bytes such that we do not get an unstable fuzzing session.
    memset(fuzz_input, 0, FUZZ_BUF_SIZE);

    // First get input from stdin:
    read(0, fuzz_input, FUZZ_BUF_SIZE-1);
    fuzz_input[FUZZ_BUF_SIZE-1] = 0; // Set last null byte just in case.
    QString paska = QString((const char*)fuzz_input);

    EVAL(paska); // Try evaluation.

    return 0; // Do not care about return value of anything. Just return zero for all cases.

}



```

The problem is that this is quite slow because it loads the application on each cycle, so we should add persistent mode to this.

Currently our fuzzing harness looks like this:

```

// This file is part of the SpeedCrunch project
// Copyright (C) 2004-2006 Ariya Hidayat <ariya@kde.org>
// Copyright (C) 2007-2009, 2013, 2016 @heldercorreia
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to
// the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA 02110-1301, USA.

#include "core/evaluator.h"
#include "core/settings.h"
#include "core/numberformatter.h"
#include "tests/testcommon.h"

#include <QtCore/QCoreApplication>

#include <string>
#include <iostream>
#include <unistd.h>

using namespace std;

typedef Quantity::Format Format;

static Evaluator* eval = 0;
static int eval_total_tests = 0;
static int eval_failed_tests = 0;
static int eval_new_failed_tests = 0;

#define CHECK_AUTOFIX(s,p) checkAutoFix(__FILE__,__LINE__,#s,s,p)
#define CHECK_DIV_BY_ZERO(s) checkDivisionByZero(__FILE__,__LINE__,#s,s)
#define CHECK_EVAL(x,y) checkEval(__FILE__,__LINE__,#x,x,y)
#define EVAL(x) tryEval(__FILE__,__LINE__,#x,x)
#define CHECK_EVAL_FORMAT(x,y) checkEval(__FILE__,__LINE__,#x,x,y,0,false,true)
#define CHECK_EVAL_KNOWN_ISSUE(x,y,n) checkEval(__FILE__,__LINE__,#x,x,y,n)
#define CHECK_EVAL_PRECISE(x,y) checkEvalPrecise(__FILE__,__LINE__,#x,x,y)
#define CHECK_EVAL_FAIL(x) checkEval(__FILE__,__LINE__,#x,x,"",0,true)
#define CHECK_EVAL_FORMAT_FAIL(x) checkEval(__FILE__,__LINE__,#x,x,"",0,true,true)
#define CHECK_USERFUNC_SET(x) checkEval(__FILE__,__LINE__,#x,x,"NaN")
#define CHECK_USERFUNC_SET_FAIL(x) checkEval(__FILE__,__LINE__,#x,x,"",0,true)

static void checkAutoFix(const char* file, int line, const char* msg, const char* expr, const char* fixed)
{
    ++eval_total_tests;

    string r = eval->autoFix(QString(expr)).toStdString();
    DisplayErrorOnMismatch(file, line, msg, r, fixed, eval_failed_tests, eval_new_failed_tests);
}

static void checkDivisionByZero(const char* file, int line, const char* msg, const QString& expr)
{
    ++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();

    if (eval->error().isEmpty()) {
        ++eval_failed_tests;
        cerr << file << "[" << line << "]\t" << msg << endl
             << "\tError: " << "division by zero not caught" << endl;
    }
}

static void checkEval(const char* file, int line, const char* msg, const QString& expr,
                      const char* expected, int issue = 0, bool shouldFail = false, bool format = false)
{
    ++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();

    if (!eval->error().isEmpty()) {
        if (!shouldFail) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tError: " << qPrintable(eval->error()) << endl;
        }
    } else {
        QString result = (format ? NumberFormatter::format(rn) : DMath::format(rn, Format::Fixed()));
        result.replace(QString::fromUtf8("−"), "-");
        if (shouldFail || result != expected) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tResult   : " << result.toLatin1().constData() << endl
                 << "\tExpected : " << (shouldFail ? "should fail" : expected) << endl;
        }
    }
}


static void tryEval(const char* file, int line, const char* msg, const QString& expr,
                      int issue = 0, bool shouldFail = false, bool format = false)
{
    //++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();
    /*
    if (!eval->error().isEmpty()) {
        if (!shouldFail) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tError: " << qPrintable(eval->error()) << endl;
        }
    } else {
        QString result = (format ? NumberFormatter::format(rn) : DMath::format(rn, Format::Fixed()));
        result.replace(QString::fromUtf8("−"), "-");
        if (shouldFail || result != expected) {
            ++eval_failed_tests;
            cerr << file << "[" << line << "]\t" << msg;
            if (issue)
                cerr << "\t[ISSUE " << issue << "]";
            else {
                cerr << "\t[NEW]";
                ++eval_new_failed_tests;
            }
            cerr << endl;
            cerr << "\tResult   : " << result.toLatin1().constData() << endl
                 << "\tExpected : " << (shouldFail ? "should fail" : expected) << endl;
        }
    }
    */

}



static void checkEvalPrecise(const char* file, int line, const char* msg, const QString& expr, const char* expected)
{
    ++eval_total_tests;

    eval->setExpression(expr);
    Quantity rn = eval->evalUpdateAns();

    // We compare up to 50 decimals, not exact number because it's often difficult
    // to represent the result as an irrational number, e.g. PI.
    string result = DMath::format(rn, Format::Fixed() + Format::Precision(50)).toStdString();
    DisplayErrorOnMismatch(file, line, msg, result, expected, eval_failed_tests, eval_new_failed_tests, 0);
}

#define FUZZ_BUF_SIZE 1000












__AFL_FUZZ_INIT();



int main(int argc, char* argv[])
{
    const char* fuzz_input[FUZZ_BUF_SIZE];
    QCoreApplication app(argc, argv);

    
    Settings* settings = Settings::instance();
    settings->angleUnit = 'r';
    settings->setRadixCharacter('.');
    settings->complexNumbers = false;
    DMath::complexMode = false;

    eval = Evaluator::instance();

    //eval->initializeBuiltInVariables();


    /*
    test_constants();
    test_exponentiation();
    test_unary();
    test_binary();

    test_divide_by_zero();
    test_radix_char();

    test_thousand_sep();
    test_sexagesimal();

    test_function_basic();
    test_function_trig();
    test_function_stat();
    test_function_logic();
    test_function_discrete();
    test_function_simplified();

    test_auto_fix_parentheses();
    test_auto_fix_ans();
    test_auto_fix_trailing_equal();
    test_auto_fix_powers();
    test_auto_fix_untouch();

    test_comments();

    test_user_functions();

    test_implicit_multiplication();
    */

    //settings->complexNumbers = true;
    DMath::complexMode = true;
    //eval->initializeBuiltInVariables();
    /*
    test_complex();
    test_format();
    test_datetime();

    test_angle_mode(settings);
    */

    // Now here is the actual main fuzzer entry point:

    // First set everything to null bytes such that we do not get an unstable fuzzing session.
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    eval->initializeBuiltInVariables();
    settings->complexNumbers = true;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        //eval->initializeBuiltInVariables();
        
        // eval->initializeBuiltInVariables();

        memset(fuzz_input, 0, FUZZ_BUF_SIZE);

        // First get input from stdin:
        //read(0, fuzz_input, FUZZ_BUF_SIZE-1);

        if (__AFL_FUZZ_TESTCASE_LEN < FUZZ_BUF_SIZE) {

            memcpy(fuzz_input, buf, __AFL_FUZZ_TESTCASE_LEN); // __AFL_FUZZ_TESTCASE_LEN
        
        } else {
        
            continue;
        
        }

        //printf("Fuzz buf is this: %s\n", fuzz_input);

        fuzz_input[FUZZ_BUF_SIZE-1] = 0; // Set last null byte just in case.
        QString paska = QString((const char*)fuzz_input);

        EVAL(paska); // Try evaluation.


    }

    return 0; // Do not care about return value of anything. Just return zero for all cases.

}


```

and seems to be reasonably fast so I am going to leave it at that. The fuzzing stability is quite poor, but I am not that worried about it.

# Identifying blindspots

After a couple of hours of fuzzing, we found no crashes, but we found plenty of paths. It seems like the tests are quite comprehensive, since we didn't find any crashes in the evaluator.

Next up it is time to compile with the coverage support and see if we can find some obvious places where the fuzzer hasn't found a path to yet. Usually these paths are where all of the bugs are, since they are in places which aren't really being tested thoroughly. After running the coverage check we can see that there aren't really that obvious places where there isn't any coverage. I will of course continue fuzzing, but it looks like this code has been tested thoroughly.

One blind spot was the modulo function. It wasn't being tested, so I added a testcase for that.

There are quite a few functions in functions.cpp which aren't being tested for, so I think I should add them, but I can't really be bothered to.

All of these functions have zero coverage:

```

   611           0 : Quantity function_binompmf(Function* f, const Function::ArgumentList& args)
     612             : {
     613           0 :     ENSURE_ARGUMENT_COUNT(3);
     614           0 :     return DMath::binomialPmf(args.at(0), args.at(1), args.at(2));
     615             : }
     616             : 
     617           0 : Quantity function_binomcdf(Function* f, const Function::ArgumentList& args)
     618             : {
     619             :     /* TODO : complex mode switch for this function */
     620           0 :     ENSURE_ARGUMENT_COUNT(3);
     621           0 :     return DMath::binomialCdf(args.at(0), args.at(1), args.at(2));
     622             : }
     623             : 
     624           0 : Quantity function_binommean(Function* f, const Function::ArgumentList& args)
     625             : {
     626             :     /* TODO : complex mode switch for this function */
     627           0 :     ENSURE_ARGUMENT_COUNT(2);
     628           0 :     return DMath::binomialMean(args.at(0), args.at(1));
     629             : }
     630             : 
     631           0 : Quantity function_binomvar(Function* f, const Function::ArgumentList& args)
     632             : {
     633             :     /* TODO : complex mode switch for this function */
     634           0 :     ENSURE_ARGUMENT_COUNT(2);
     635           0 :     return DMath::binomialVariance(args.at(0), args.at(1));
     636             : }
     637             : 
     638           0 : Quantity function_hyperpmf(Function* f, const Function::ArgumentList& args)
     639             : {
     640             :     /* TODO : complex mode switch for this function */
     641           0 :     ENSURE_ARGUMENT_COUNT(4);
     642           0 :     return DMath::hypergeometricPmf(args.at(0), args.at(1), args.at(2), args.at(3));
     643             : }
     644             : 
     645           0 : Quantity function_hypercdf(Function* f, const Function::ArgumentList& args)
     646             : {
     647             :     /* TODO : complex mode switch for this function */
     648           0 :     ENSURE_ARGUMENT_COUNT(4);
     649           0 :     return DMath::hypergeometricCdf(args.at(0), args.at(1), args.at(2), args.at(3));
     650             : }
     651             : 
     652           0 : Quantity function_hypermean(Function* f, const Function::ArgumentList& args)
     653             : {
     654             :     /* TODO : complex mode switch for this function */
     655           0 :     ENSURE_ARGUMENT_COUNT(3);
     656           0 :     return DMath::hypergeometricMean(args.at(0), args.at(1), args.at(2));
     657             : }
     658             : 
     659           0 : Quantity function_hypervar(Function* f, const Function::ArgumentList& args)
     660             : {
     661             :     /* TODO : complex mode switch for this function */
     662           0 :     ENSURE_ARGUMENT_COUNT(3);
     663           0 :     return DMath::hypergeometricVariance(args.at(0), args.at(1), args.at(2));
     664             : }
     665             : 
     666           0 : Quantity function_poipmf(Function* f, const Function::ArgumentList& args)
     667             : {
     668             :     /* TODO : complex mode switch for this function */
     669           0 :     ENSURE_ARGUMENT_COUNT(2);
     670           0 :     return DMath::poissonPmf(args.at(0), args.at(1));
     671             : }
     672             : 
     673           0 : Quantity function_poicdf(Function* f, const Function::ArgumentList& args)
     674             : {
     675             :     /* TODO : complex mode switch for this function */
     676           0 :     ENSURE_ARGUMENT_COUNT(2);
     677           0 :     return DMath::poissonCdf(args.at(0), args.at(1));
     678             : }
     679             : 
     680           0 : Quantity function_poimean(Function* f, const Function::ArgumentList& args)
     681             : {
     682             :     /* TODO : complex mode switch for this function */
     683           0 :     ENSURE_ARGUMENT_COUNT(1);
     684           0 :     return DMath::poissonMean(args.at(0));
     685             : }
     686             : 
     687           0 : Quantity function_poivar(Function* f, const Function::ArgumentList& args)
     688             : {
     689             :     /* TODO : complex mode switch for this function */
     690           0 :     ENSURE_ARGUMENT_COUNT(1);
     691           0 :     return DMath::poissonVariance(args.at(0));
     692             : }
     693             : 
     694           0 : Quantity function_mask(Function* f, const Function::ArgumentList& args)
     695             : {
     696             :     /* TODO : complex mode switch for this function */
     697           0 :     ENSURE_ARGUMENT_COUNT(2);
     698           0 :     return DMath::mask(args.at(0), args.at(1));
     699             : }
     700             : 
     701           0 : Quantity function_unmask(Function* f, const Function::ArgumentList& args)
     702             : {
     703             :     /* TODO : complex mode switch for this function */
     704           0 :     ENSURE_ARGUMENT_COUNT(2);
     705           0 :     return DMath::sgnext(args.at(0), args.at(1));
     706             : }
     707             : 

```

but I don't think that it is that much of a problem, because I doubt that those are actually interesting from a bug hunting point of view.





































