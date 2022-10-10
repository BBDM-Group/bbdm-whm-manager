```
>>> ========================================================== <<<
>>>              _                                             <<<
>>>   __      __| |__    __ _  _ __ ___   _ __   _   _         <<<
>>>   \ \ /\ / /| '_ \  / _` || '_ ` _ \ | '_ \ | | | |        <<<
>>>    \ V  V / | | | || (_| || | | | | || |_) || |_| |        <<<
>>>     \_/\_/  |_| |_| \__,_||_| |_| |_|| .__/  \__, |        <<<
>>>                                      |_|     |___/         <<<
>>> ========================================================== <<<
```

# Description

This is a first version of the Python WHM API interface library
While it was inspired by SIRBUGS script to create CPanels, while trying to adapt it
to use as a library - it was completely reworked. 
In the first version only a generic function call is implemented, which allows full control of
the WHM panel, but lacks "convenience" functions for mostly used specific WHM Api functions.

# Setup

```bash
$ pip install whambampy
```

# Usage

```python
def create_cpanel():
    from whambampy import whm

    whm = whm(host='example.com', username='whmuser', api_token='mysecuretoken')
    result = whm.call(function='createacct', username='newuser', domain='new.example.com')

    if 'Creation Ok' in result['metadata'].get('reason'):
        return True
```


Full list of WHM Api functions can be found in `api_commands.py`

Documentation regarding api contracts for each function can be found at `https://api.docs.cpanel.net/openapi/whm/operation/{{ function_name }}`


Suggestions and contributions are always welcome. Any found bugs should be filed in issues 