# laracrypt

Laracrypt is a package which provides Laravel compatible cryptography in Python. This is absolutely useful when you want to pass in the data between your Laravel and Python projects.

It, for sure, supports Python 3.6+. I have not tested this in any lower version. If you ever test it, please update this README doc through a pull request.

### Usage

**Encryption:**
```python
from laracrypt import LaraCrypt

lc = LaraCrypt("Laravel Key")
encrypted_text = lc.encrypt("Your secret data")

```

**Decryption:**
```python
from laracrypt import LaraCrypt

lc = LaraCrypt("Laravel Key")
plain_text = lc.decrypt("Laravel encrypted string")

```

### Dependencies

Install the dependencies with the following command
```commandline
pip install pycryptodome phpserialize
```


## Bugs and Improvements
In case you find any issue with the code, please file them in our [issue tracker](https://github.com/kodephreak/laracrypt/issues). You are free to make fixes and improvements yourself. Just raise a pull request. 
