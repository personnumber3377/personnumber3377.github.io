
# Fuzzing django for SQL injection

Ok, so I think that fuzzing django for SQL injection is a good idea, because there has been quite a few SQLI vulns recently.

Let's take a deep dive into the structure of django and see what we can maybe do??? I found this here: https://security.snyk.io/vuln/SNYK-PYTHON-DJANGO-7642814 which seems quite juicy.

test_extract_trunc.py:

```

        with self.assertRaises((OperationalError, ValueError)):
            DTModel.objects.filter(
                start_datetime__year=Extract(
                    "start_datetime", "day' FROM start_datetime)) OR 1=1;--"
                )
            ).exists()

```

At one point I got this error here:

```

Here is the string: /8/
Here is the string: /8/
Here is the string: /8/__dict__
Here is the string: /8/_
Here is the string: /8_
Here is the string:
Here is the string: ___ic:_dt/
Here is the string: ___ih:_dt/
Here is the string: _`_ih:_dt/
Here is the string: __dict__t/
Here is the string: _9\_dict__t/
Here is the string: ___________u_____u_____________u__7_
Here is the string: _________u_______u_____________u__7_
Here is the string: _________u_______u_____________u__7&
Here is the string: _________u_____7&u_____________u__7&
Here is the string: _________u_____7&u____________Ou__7&
Here is the string: __7____
Here is the string: __7__
Here is the string: _7__
Here is the string: _7_
Here is the string: _7_
Here is the string: ___________________/________________O______/_____________________7_
Here is the string: ___________________/________________O______/_____________________7_
Here is the string: ___________________/________________O______/_____________________7_
Here is the string: ___________________/________________________7_
Here is the string: ___________________/___________^____________7_
Here is the string: 98\
Here is the string: __dict__98\
Here is the string: __dact__98\
Here is the string: __dact__98\__dict__
Here is the string: __dact__98\/_dict__
Here is the string: 8]
Here is the string: 8U
Here is the string:
Here is the string: ____________ct_,_
Here is the string: ____________lt_,_
Here is the string: ____________lt_____lt_,_,_
Cannot resolve keyword '' into field. Join on 'data' not permitted.
Exception encountered!!!!

 === Uncaught Python exception: ===
FieldError: Cannot resolve keyword '' into field. Join on 'data' not permitted.
Traceback (most recent call last):
  File "/home/oof/djangosqlifuzz/django-fuzzers/fuzz_sqli.py", line 13, in TestOneInput
    fuzzers_sqli.fuzz_sqli(data)
  File "/home/oof/djangosqlifuzz/django-fuzzers/fuzzers_sqli.py", line 153, in fuzz_sqli
    func(test_string) # Call target function
    ^^^^^^^^^^^^^^^^^
  File "/home/oof/djangosqlifuzz/django-fuzzers/fuzzers_sqli.py", line 129, in target_queryset_alias_json_field2
    res = JSONFieldModel.objects.values_list(f"data__{test_string}")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/manager.py", line 87, in manager_method
    return getattr(self.get_queryset(), name)(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/query.py", line 1405, in values_list
    clone = self._values(*_fields, **expressions)
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/query.py", line 1359, in _values
    clone.query.set_values(fields)
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 2560, in set_values
    self.add_fields(field_names, True)
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 2243, in add_fields
    cols.append(join_info.transform_function(target, final_alias))
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1924, in transform
    raise last_field_exception
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1919, in transform
    wrapped = previous(field, alias)
              ^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1924, in transform
    raise last_field_exception
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1919, in transform
    wrapped = previous(field, alias)
              ^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1924, in transform
    raise last_field_exception
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1897, in setup_joins
    path, final_field, targets, rest = self.names_to_path(
                                       ^^^^^^^^^^^^^^^^^^^
  File "/home/oof/atheris-venv/lib/python3.11/site-packages/django/db/models/sql/query.py", line 1839, in names_to_path
    raise FieldError(
FieldError: Cannot resolve keyword '' into field. Join on 'data' not permitted.

==886621== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited
MS: 3 InsertByte-ChangeBinInt-CopyPart-; base unit: ea99a803963bb51fea943843c0f0d951a9c2ac83
0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x5f,0x6c,0x74,0x5f,0x5f,0x5f,0x5f,0x5f,0x6c,0x74,0x5f,0x2c,0x5f,0x2c,0x5f,
____________lt_____lt_,_,_
artifact_prefix='./'; Test unit written to ./crash-8ca2dfd5d19314460e3860f7dbdc808c10ce595d
Base64: X19fX19fX19fX19fbHRfX19fX2x0XyxfLF8=

```

but this seems to be by design and not SQLI...

## Adding a generic thing

Ok, so maybe like this???

```

# All known expression models
expression_model_names = [
    "Manager", "Employee", "RemoteEmployee", "Company", "Number", "Experiment",
    "Result", "Time", "SimulationRun", "UUIDPK", "UUID", "JSONFieldModel",
    "Author", "Publisher", "Book", "Store", "Employee_aggregation", "DTModel"
]

# The interesting ORM methods to target
interesting_methods = ["filter", "values", "values_list", "annotate", "aggregate", "exclude"]

def dynamic_fuzz_target(test_string):
    # Random model and ORM method
    model_name = random.choice(expression_model_names)
    method_name = random.choice(interesting_methods)

    # Get the model class from app registry
    Model = apps.get_model('app', model_name)
    manager = Model.objects

    # Check if method exists and is callable
    if not hasattr(manager, method_name):
        print(f"{method_name} not available on {model_name}")
        return

    method = getattr(manager, method_name)
    if not callable(method):
        print(f"{method_name} is not callable on {model_name}")
        return

    try:
        # Generate test input
        if method_name in ("values", "values_list"):
            res = method(f"{test_string}")
        elif method_name in ("filter", "exclude"):
            res = method(**{f"{test_string}": F("id")})
        elif method_name == "annotate":
            res = method(**{f"{test_string}": F("id")})
        elif method_name == "aggregate":
            # These expect aggregations like Sum('field'), so not fuzzing-friendly; skip or simulate
            return
        else:
            return

        # Evaluate the queryset to trigger potential DB errors
        list(res)  # force evaluation
    except Exception as e:
        print("Exception caught:", type(e).__name__, str(e))
        raise  # or log it for crash deduplication

```


Now I am getting this stuff here:

```

Here is the string: _DateField_____
Exception caught: FieldError Cannot resolve keyword '_DateField' into field. Choices are: id, uuid, uuid_fk, uuid_fk_id
Here is the string: __\?\
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: duration, id, name, num_awards
Here is the string: __\[\
Here is the string: __\[[\
Exception caught: ValueError Column aliases cannot contain whitespace characters, quotation marks, semicolons, or SQL comments.
Here is the string: __\[' UNION SELECT 1, 'abc', NULL --[\
Here is the string: __\['[ UNION SELECT 1, 'abc', NULL --[\
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: age, friends, id, name, rating
Here is the string: __DateFi_Bo_Bo_te//onFi+dd\
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: authors, contact, contact_id, id, isbn, name, pages, price, pubdate, publisher, publisher_id, rating
Here is the string: __DateFi_Bo_Bo_te//onFi+dd\
Here is the string: __DateFi_Bo_Bo_te//onFi+dd\
Here is the string: ___________u________u__________/_____________~_______________u__3____Bo_Bo
Here is the string: ___________u________u__________/_____________~_______________u__4____Bo_Bo
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: based_in_eu, ceo, ceo_id, id, name, num_chairs, num_employees, point_of_contact, point_of_contact_id
Here is the string: ___________u________D__________/_____________~_______________u__4____Bo_Bo
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: id
Here is the string: ___________u________D__________/_____________~_______________u__4____Bo_Bo
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: duration, end_date, end_datetime, end_time, id, name, start_date, start_datetime, start_time
Here is the string: ___________u________D_____________u__4____Bo_Bo
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: id, work_day_preferences
Here is the string: ___________u________u__________/_____________~_______________u__3___
Here is the string: ___________u________u____________/_____________~_______________u__3___
Here is the string: ___________u_____   __u____________/_____________~_______________u__3___
Here is the string: __?\\
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: based_in_eu, firstname, id, lastname, manager, manager_id, salary
Here is the string: _________________________
Here is the string: ____________________________________________
Here is the string: ___________________________________._________
Here is the string: _______________________________._________
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: id
Here is the string: _________________________________
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: data, id
Here is the string: __dBooleanField_dict__:/
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: data, id
Here is the string: _______________________6_
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: decimal_value, float, id, integer
Here is the string: _____________=_________6_
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: id, name, secretary, secretary_id
Here is the string: _________=_________6_
Here is the string: _________=_________2_
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: decimal_value, float, id, integer
Here is the string: _________=_____2_
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: books, friday_night_closing, id, name, original_opening
Here is the string: __________b__________________
Here is the string: ________{__b__________________
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: age, friends, id, name, rating
Here is the string: __dt__:/
Here is the string: __
Here is the string: __
Here is the string: __44
Here is the string: __4__444
Exception caught: FieldError Cannot resolve keyword '' into field. Choices are: assigned, completed, end, estimated_time, id, name, scalar, start
Here is the string: 9
Here is the string: 9
Here is the string: 9
Here is the string: 9
Here is the string: _admin' #_mf\
Exception caught: ValueError Column aliases cannot contain whitespace characters, quotation marks, semicolons, or SQL comments.
Here is the string: _admin#'m_ f\
Exception caught: FieldError Cannot resolve keyword '_admin#'m_ f\' into field. Choices are: end, end_id, id, midpoint, start, start_id
Here is the string: _admDateFieldin#'m_ f\
Exception caught: FieldError Cannot resolve keyword '_admDateFieldin#'m_ f\' into field. Choices are: based_in_eu, ceo, ceo_id, id, name, num_chairs, num_employees, point_of_contact, point_of_contact_id
Here is the string: _admDateFieldiDateFieldn#'m_ f\
Exception caught: FieldError Cannot resolve keyword '_admDateFieldiDateFieldn#'m_ f\' into field. Choices are: id, uuid, uuid_fk, uuid_fk_id
Here is the string: _admDateFieldiDateieldn#'m_ f\
Here is the string: 1
Here is the string: 0
Here is the string: 0
Here is the string: L
Here is the string: ' OR EXISTS(SELECT * FROM users) --L
Here is the string: _
Here is the string: __
Here is the string: __
Here is the string: ' OR benchmark(10000000,MD5(1))--__
Here is the string: 9/
Here is the string: _t9/
Exception caught: FieldError Cannot resolve keyword '_t9/' into field. Choices are: duration, id, name, num_awards
Here is the string: 9_t9/
Here is the string: 9__t9/
Here is the string: 9__tt9
Here is the string: 9|
Here is the string: |
Here is the string: -|
^CKeyboardInterrupt: stopping.

```



Maybe cutout the stuff and add them into the fuzzing dictionary????

```


def s():
	fh = open("choices.txt", "r")
	lines = fh.readlines()
	fh.close()
	output = set()
	# Choices are:
	sep = "Choices are: "
	for line in lines:
		line = line[line.index(sep)+len(sep):]
		if "\n" == line[-1]: # Cutout newline
			line = line[:-1]
		print(line)
		things = line.split(", ")
		for thing in things:
			output.add(thing) # Add the thing.
	for thing in list(output):
		print("\""+str(thing)+"\"")
	return


if __name__=="__main__":
	s()
	exit(0)


```

Done!











































