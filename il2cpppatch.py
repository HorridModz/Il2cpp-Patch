# https://github.com/HorridModz/Il2cppPatch

def main():
    """
    Welcome!

    Edit this function according to the instructions to generate your script!
    """

    """
    Path to the dumpcs file
    Make sure not to remove the r before the opening quotation mark!
    """
    dumpcspath = r"C:\Users\zachy\Documents\Work\Projects\Pixel Gun 3D\Pixel Gun 3D 22.6.0\dump.cs"  # noqa
    """
    Path to the .so library file (usually libil2cpp.so)
    Make sure not to remove the r before the opening quotation mark!
    """
    libpath = r"C:\Users\zachy\Documents\Work\Projects\Pixel Gun 3D\Pixel Gun 3D 22.6.0\libil2cpp.so"  # noqa
    """
    Path to the output script file
    Make sure not to remove the r before the opening quotation mark!
    """
    outputpath = r"C:\Users\zachy\Downloads\il2cpppatchgeneratedscript.lua"  # noqa

    """
    Settings for generated script
    
    scripttitle: Title of the script.
    scriptauthor: Your name. To make it anonymous, set to None.
    scriptdescription: Description of what the script does. Note that all special characters will be escaped.
                 Also note that double quotes (") must be escaped (written as \") or in a multiline string.
                 To not have a description, set to None.
    scriptalert: Script will alert this message when it is run. Note that all special characters will be escaped.
                 Also note that double quotes (") must be escaped (written as \") or in a multiline string.
                 To disable, set to None.
    scripttoast: Script will toast this message when it is run. Note that all special characters will be escaped.
                 Also note that double quotes (") must be escaped (written as \") or in a multiline string.
                 To disable, set to None.
    
    Example alert (demonstrating with multiline raw string) - note that the opening and closing quotes are escaped with
    backward slashes, so pretend the backslashes aren't there):
    
    scriptalert = r\"\"\"Welcome to my script!
This script will give you 10000 gems. Enjoy! As they say, "A happy man is a wealthy man."\"\"\"
    """

    scripttitle = "My Il2cppPatch Script"
    scriptdescription = None
    scriptauthor = "User123456789#6424"
    scriptalert = None
    scripttoast = None

    """
    Game info
    
    gamename: Name of the game the script is for.
    gameversion: Game version the script is for.
    architecture: Game architecture the script is for (32bit or 64bit).
    """
    gamename = "Pixel Gun 3D"
    gameversion = "22.6.0"
    global architecture
    architecture = "64bit"  # 32bit or 64bit

    """
    Initialization of script (do not touch this)
    """
    script = Script()
    script.addopeningcomment(scripttitle, scriptdescription, scriptauthor, gamename, gameversion, architecture)
    if scriptalert is not None:
        # noinspection PyTypeChecker
        script.addalert(scriptalert)
    if scripttoast is not None:
        # noinspection PyTypeChecker
        script.addtoast(scripttoast)
    script.addarchitecturecheck(architecture)

    """ Patching time! """

    """
    Patching functions
    
    getmethodandclassfromoffset: Function to get the class name and method name of a method from its offset
    
    Arguments:
    
    Offset: Offset of the method
    
    Use it in place of classname and methodname, with * at the beginning, like this:
    *getmethodandclassfromoffset(offset)
    
    For example:
    
    patchmethod(*getmethodandclassfromoffset(0x69420), 69, "int") 
    
    getfieldfromclassandoffset: Function to get the name of a field by the name of its class and the field offset
    
    Arguments:
    
    classname: Name of the class the field is in
    offset: Offset of the field (mutually exclusive with offset)
    
    Use it in place of fieldname, like this:
     
    patchfield(getfieldfromclassandoffset("MyClass", 0x69), 69, "int") 
    
    Patchmethod: Function to patch one method.

    Arguments:

    classname: Name of the class the method is in.
    methodname: Name of the method to patch.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.

    Patchfield: Function to patch one field.

    Arguments:

    classname: Name of the class the field is in.
    fieldname: Name of the field to patch.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    freeze: Whether to freeze the field, so it cannot be modified by the game after it is patched. Default false.
            NOTE: If there is no Update method in the field's class, another class's Update method will be hooked to 
            freeze the field (it will take the first Update() method it finds).
    updatemethod: Optional, only applicable is freeze is true. Force the program to update (freeze) the fields every 
                  time this method is called. Using an Update method is recommended, as these are called at the
                  beginning of every frame. This is only useful if there is no Update method in the field's class;
                  however, this should still not be needed since the program will search for other Update methods in the
                  event that the field's class does not have one.
    
    Freezefield: Function to freeze one field, so it cannot be modified by the game after it is patched.
                 NOTE: If there is no Update method in the field's class and updatemethod is not provided, 
                 another class's Update method will be hooked to freeze the field (it will take the first Update 
                 method it finds).

    Arguments:

    classname: Name of the class the freeze is in.
    fieldname: Name of the field to freeze.
    updatemethod: Optional. Force the program to update (freeze) the field every time this method is called. Using 
                  an Update method is recommended, as these are called at the beginning of every frame. This is 
                  only useful if there is no Update method in the field's class; however, this should still not be 
                  needed since the program will search for other Update methods in the event that the field's class 
                  does not have one.
    
    Restoremethod: Function to revert patched method back to original
    
    Arguments:

    classname: Name of the class the method is in.
    methodname: Name of the method to restore.
    
    Restorefield: Function to revert patched field back to original value
    
    Arguments:

    classname: Name of the class the field is in.
    fieldname: Name of the field to restore.
    unfreeze: Whether to unfreeze the field (default true).
    
    Patchallmethods: Function to patch all methods in a class.
    
    Arguments:
    
    classname: Name of the class to patch.
    namecontains: Only patch methods that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only patch methods that are of this data type. Only supports primitive and non-nullable data types. 
              Defaults to any (though it will fail on methods with data types incompatible with your patchtype).
    modifiers: Only patch methods that contain these modifiers (list).
               Examples: ["public", "static"], "overload"
               Defaults to None.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    
    Patchallfields: Function to patch all fields in a class.
    
    Arguments:
    
    classname: Name of the class to patch.
    namecontains: Only patch fields that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only patch fields that are of this data type. Only supports primitive and non-nullable data types.
              This is not case sensitive.
              Defaults to any (though it will fail on fields with data types incompatible with your patchtype).
    modifiers: Only patch fields that contain these modifiers (list).
               Examples: ["public", "protected"], "readonly"
               Defaults to None.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    freeze: Whether to freeze all patched fields
            NOTE: If there is no Update method in the class and updatemethod is not provided, 
            another class's Update method will be hooked to freeze the fields (it will take the first Update method it 
            finds).
    updatemethod: Optional, only applicable is freeze is true. Force the program to update (freeze) the fields every 
                  time this method is called. Using an Update method is recommended, as these are called at the
                  beginning of every frame. This is only useful if there is no Update method in the field's class;
                  however, this should still not be needed since the program will search for other Update methods in the
                  event that the field's class does not have one.
    
    Freezeallfields: Function to freeze all fields in a class.
                    NOTE: If there is no Update method in the class and updatemethod is not provided, 
                    another class's Update method will be hooked to freeze the fields (it will take the first Update
                    method it finds).
    
    Arguments:
    
    classname: Name of the class to patch.
    namecontains: Only freeze fields that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only freeze fields that are of this data type. Only supports primitive and non-nullable data types.
              This is not case sensitive.
              Defaults to any (though it will fail on methods with data types incompatible with your patchtype).
    modifiers: Only freeze fields that contain these modifiers (list).
               Examples: ["public", "protected"], "readonly"
               Defaults to None.
    updatemethod: Optional, only applicable is freeze is true. Force the program to update (freeze) the fields every 
                  time this method is called. Using an Update method is recommended, as these are called at the
                  beginning of every frame. This is only useful if there is no Update method in the field's class;
                  however, this should still not be needed since the program will search for other Update methods in the
                  event that the class does not have one.
    
    Unfreezeallfields: Function to unfreeze all fields in a class.
    
    Arguments:
    
    classname: Name of the class to patch.
    namecontains: Only unfreeze fields that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only unfreeze fields that are of this data type. Only supports primitive and non-nullable data types.
              This is not case sensitive.
              Defaults to any (though it will fail on methods with data types incompatible with your patchtype).
    modifiers: Only unfreeze fields that contain these modifiers (list).
               Examples: ["public", "protected"], "readonly"
               Defaults to None.
    
    
    Restoreallmethodsinclass: Function to revert all patched methods in a class
 
    Arguments:

    classname: Name of the class to revert methods / fields in.
    
    
    Restoreallfieldsinclass: Function to revert all patched fields in a class
 
    Arguments:

    classname: Name of the class to revert methods / fields in.
    unfreeze: Whether to unfreeze all fields in class
    
    
    callmethod: Function to call one method
    
    Arguments:

    classname: Name of the class the method is in.
    methodname: Name of the method to call.
    params: List of parameters to call the method with, in this format: datatype value
            Only supports primitive types. Does not support nullable types, either.
            Examples: "int": 1, "string": "hello", None: "null", "null": "null"
            If there are no parameters, pass an empty list or None.
            Params much match method's signature (it will also work if convertparams is true
            and the params can be converted to match the signature).
    times: Number of times to call the method. Must be greater than 0.
           Defaults to 1.
    delaymillisecs: The delay (in milliseconds) between calling the method. Only matters if times is greater than 1. 
                    Set to 0 or None to have no delay. This delay will not apply before the first call(s) or after the
                    last call(s), just in between.
                    Defaults to None (no delay).
    convertparams: Whether to attempt to convert parameters to other data types in order to match
                   the method's signature.
                   Defaults to True.
    
    redirectmethod: Function to redirect a methods in a class to call another method.
    
    Arguments:
    
    classname: Name of the class the method is in.
    methodname: Name of the method to call.
    methodtocall: Method to redirect this method to.
    params: Dictionary of parameters to call the method it is redirected to with, in this format: "data type": value
            If you want it to use one of the original method's parameters:
                Set the value to MethodParam (NUMBEROFPARAMETER). For example: "int": MethodParam(1).
            Of course, you can also use your own parameters:
                If the value is null, the data type should be None (without quotes) or "null"
                Only supports primitive types. Does not support nullable types, either.
                Examples: "int": 1, "string": "hello", None: "null", "null": "null"
    
    callandredirectmethod: Same as redirectmethod, but calls the original method as well. Function to redirect 
    a method to call another method.
    
    Arguments:
    
    classname: Name of the class the method is in.
    methodname: Name of the method to call.
    methodtocall: Method to redirect this method to.
    params: Dictionary of parameters to call the method it is redirected to with, in this format: "data type": value
            If you want it to use one of the original method's parameters:
                Set the value to MethodParam (NUMBEROFPARAMETER). For example: "int": MethodParam(1).
            Of course, you can also use your own parameters:
                If the value is null, the data type should be None (without quotes) or "null"
                Only supports primitive types. Does not support nullable types, either.
                Examples: "int": 1, "string": "hello", None: "null", "null": "null"
    callafter: Whether to call the original method before or after the redirected one (False is before, True is after).
               This default to False (before).
    
    callallmethods: Function to call all methods in a class.
    
    Arguments:
    
    classname: Name of the class to call the methods from.
    namecontains: Only call methods that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only call methods that are of this data type. Can include modifiers, such
        as static, and access modifiers, such as public.
        This is not case sensitive.
        Examples: int, static void, public Dictionary<string, SaltedInt> 
        Defaults to any.
    params: Dictionary of parameters to call the method with, in this format: "data type": value
            If the value is null, the data type should be None (without quotes) or "null"
            Only supports primitive types. Does not support nullable types, either.
            Examples: "int": 1, "string": "hello", None: "null", "null": "null"
            Only calls methods that follow this signature of params / have default arguments for unprovided params (or
            if convertparams is true and the params can be converted to match the signature).
    times: Number of times to call the methods. Must be greater than 0.
           Defaults to 1.
    delaymillisecs: The delay (in milliseconds) between calling the methods. Only matters if times is greater than 1. 
                    Set to 0 or None to have no delay. This delay will not apply before the first call(s) or after the
                    last call(s), just in between.
                    Defaults to None (no delay).
    convertparams: Whether to attempt to convert parameters to other data types in order to match method
                   signatures.
                   Defaults to True.
    
    
    redirectallmethods: Function to redirect all methods in a class to call another method.
    
    Arguments:
    
    classname: Name of the class to patch.
    namecontains: Only redirect methods that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only redirect methods that are of this data type. Only supports primitive and non-nullable data types. 
              Defaults to any (though it will fail on methods with data types incompatible with your patchtype).
    modifiers: Only redirect methods that contain these modifiers (list).
               Examples: ["public", "static"], "overload"
               Defaults to None.
    methodtocall: Method to redirect these methods to.
    params: Dictionary of parameters to call the method they are redirected to with, in this format: "data type": value
            If you want it to use one of the original method's parameters:
                Set the value to MethodParam (NUMBEROFPARAMETER). For example: "int": MethodParam(1). If the 
                original method has too little parameters, it will be skipped.
            You can also make it use the first method parameter of a certain data type:
                Set the value to MethodParamofType(DATATYPE). (If you do this twice 
                with the same data type, the next instance will use the next parameter of that data type, and so on).
                If the original method does not have enough parameters of this data type, it will be skipped.
                For example: MethodParamofType("int")
            Of course, you can also use your own parameters:
                If the value is null, the data type should be None (without quotes) or "null"
                Only supports primitive types. Does not support nullable types, either.
                Examples: "int": 1, "string": "hello", None: "null", "null": "null"
    
    callandredirectallmethods: Same as redirectallmethods, but calls the original methods as well. Function to redirect 
    all methods in a class to call another method.
    
    Arguments:
    
    classname: Name of the class to patch.
    namecontains: Only redirect methods that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only redirect methods that are of this data type. Only supports primitive and non-nullable data types. 
              Defaults to any (though it will fail on methods with data types incompatible with your patchtype).
    modifiers: Only redirect methods that contain these modifiers (list).
               Examples: ["public", "static"], "overload"
               Defaults to None.
    methodtocall: Method to redirect these methods to.
    params: Dictionary of parameters to call the method they are redirected to with, in this format: "data type": value
            If you want it to use one of the original method's parameters:
                Set the value to MethodParam (NUMBEROFPARAMETER). For example: "int": MethodParam(1). If the 
                original method has too little parameters, it will be skipped.
            You can also make it use the first method parameter of a certain data type:
                Set the value to MethodParamofType(DATATYPE). (If you do this twice 
                with the same data type, the next instance will use the next parameter of that data type, and so on).
                If the original method does not have enough parameters of this data type, it will be skipped.
                For example: MethodParamofType("int")
            Of course, you can also use your own parameters:
                If the value is null, the data type should be None (without quotes) or "null"
                Only supports primitive types. Does not support nullable types, either.
                Examples: "int": 1, "string": "hello", None: "null", "null": "null"
    callafter: Whether to call the original method before or after the redirected one (False is before, True is after).
               This default to False (before).
    
    
    getmethodreturn: Function to call one method and get its return. The same as callmethod, but for getting the method
                     return. Not applicable to void methods. Can be used in other patches, such as for a 
                     method parameter. Can also be embedded into your code in addcustomcode().
    
    Arguments:

    classname: Name of the class the method is in.
    methodname: Name of the method to call.
    params: List of parameters to call the method with, in this format: datatype value
            Only supports primitive types. Does not support nullable types, either.
            Examples: "int": 1, "string": "hello", None: "null", "null": "null"
            If there are no parameters, pass an empty list or None.
            Params much match method's signature (it will also work if convertparams is true
            and the params can be converted to match the signature).
    convertparams: Whether to attempt to convert parameters to other data types in order to match
                   the method's signature.
                   Defaults to True.
    
    getfieldvalue: Function to get value of a field within the script. Can be used in other patches, such as for a 
                   method parameter. Can also be embedded into your code in addcustomcode().
    
    Arguments:
    
    classname: Name of the class the field is in
    name: Name of the field (mutually exclusive with offset)
    
    
    addcustomcode: Function to your own gameguardian lua code to the script along with all your patches. You can include
                   patches in your own code, which is especially useful for user-controlled mod menus, debugging, 
                   etc. This function just gives you more control than using the patches themselves and using this tool
                   to write the entire script.
                   
    Arguments:
    
    code: Code to add to the script. Will be added as the next line after the most recent patch. It is recommended to
          a multiline string for readability (so you don't have to escape quotes and you can include newlines).
          Beware of special characters and escape sequences such as backslash (\) and newline (\n) - you may want to 
          create a raw string by  placing "r" before your opening quotes, so special characters and escape sequences 
          are ignored. Use an f-string or python's format function to embed the result of other functions in your code.
    
    Example (note that the opening and closing quotes are escaped with backward slashes, so pretend the backslashes 
            aren't there):
    
    addcustomcode(r\"\"\"
gg.alert("Welcome to my script!")
gg.alert("You have: {} gems")
gg.alert("Adding 10,000 more!")\"\"\".format(getfield("PlayerCurrency", "gems"))
    callmethod("PlayerCurrency", "AddGems", {"int": 10000})
    addcustomcode(r\"\"\"
gg.alert("Success! You now have: {} gems").format(getfield("PlayerCurrency", "gems"))
    """

    """
    Patchtype:
    
    The type of data a patch is.
    Unfortunately, primitive / not-nullable data types are not supported.
    If the patch is invalid for a field or method, the program will try to convert the patch value
    to another representation that means the same thing. If it fails to do so, it will throw an error and
    skip the method / field.
    . HexPatch: Arm instructions in hexadecimal representation. If used on a field, it
        will fail.
    . ArmPatch: Arm assembly code for 32bit (arm) or 64bit (arm64).
        Separate instructions with newlines or semicolons. If used on a field, it will fail.
    . NOPPatch: Use on void methods to make them do nothing. An example usage is implementing
        antiban by nopping a Ban method. When this type of patch is used, the patchto value does not matter.
        For consistency, I recommend setting patchto to None. If used on a field, it
        will fail.
    . IntPatch: Whole number. If patchto is a decimal number, the value will be
        rounded to the nearest whole number and a warning will be given. Works for int, char, float, double,
        byte, and boolean data types. If the value exceeds the integer limit of the data type of the method
        or field, it will fail. Can be negative, but if the data type of the method or field is unsigned,
        it will fail.
    . BoolPatch: True or False. Can be python built-in True or False.
        Can also be a string with the value of "true" or "false", which is not case-sensitive.
        Can also be 1 (true) or 0 (false).
    . FloatPatch: Whole number or decimal number. Works for both float
        and double data types. If the number cannot be represented, it will be rounded and a warning will
        be giveh. If the value exceeds the float / double limit of the data type of the method or field,
        it will fail. Also works for int, char, float, double, byte, and boolean data types if the value
        is a whole  number, though it is recommended to use Int instead of Float in this case.
        Can be negative, but if the data type of the method or field is unsigned, it will fail.
    . StringPatch: Text. If any of the characters in the string are not in the UTF-16 charset,
        it will fail. Also works for char data type if the value is only one character long.
    - CharPatch: Single character that is in the UTF-16 charset. Can be a unicode code point,
        a unicode sequence, or a one-character-long string.
        If it is a string that is shorter or longer than one character, it will fail. If it is a unicode
        code point or unicode sequence that is not in the UTF-16 charset, it will fail.
        Also works for string data type.
    """
    # noinspection IncorrectFormatting
    patches.append(MethodPatch(NOPPatch(), Method("Player", "Ban", "void", "0x69")))

    """
    Building and outputting your script (do not touch this)
    """
    script.addpatches(patches)
    try:
        with open(outputpath, "w") as f:
            f.write(script.code)
    except UnicodeEncodeError:
        #  In case there's non-ascii characters and locale is not set to utf-8 - as is default as windows. Fixes that
        #  pesky problem.
        with open(outputpath, "w", encoding="utf8") as f:
            f.write(script.code)


"""
Everything below here is the code that makes it work - you don't need to look at this!
It's all in one file, so the code is kind of cluttered and messy.
"""


def patchallmethods():
    """
    Patches all methods, fields, or both in a class.
    """


def patchmethod():
    """
    Patches a single method
    """


def patchfield():
    """
    Patches a single field.
    """


def callmethod():
    """
    Calls a single method.
    """
    # TODO: Still create hex patch (just don't call .Modify()) - so it can call .Restore() later.


def callall():
    """
    Calls all methods in an entire class.
    """


"""
Requiring python 3.11 or later
"""
import sys

# From https://stackoverflow.com/a/34911547/20558255
if sys.version_info < (3, 11):
    # noinspection PyStringFormat
    sys.exit("""Python 3.11 or later is required. You currently have Python %s.%s installed.
Download the latest version of Python from https://www.python.org/downloads/""" % sys.version_info[:2])

"""
Installing and importing modules
"""
from typing import List, Dict, Sequence, Any, Optional, Union, TypeVar, overload
import os
import importlib
import pkg_resources
import subprocess
import re
import json
from weakref import finalize
from enum import Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass


def install_module(requirement: str):
    # Get name of requirement (separate from version)
    requirementname = re.split(r"\s|~|=|>|<", requirement)[0]
    try:
        pkg_resources.get_distribution(requirement)
    except pkg_resources.ResolutionError:
        print(f"Installing {requirementname} module...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", requirement, "--disable-pip-version-check"],
                                  stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise ImportError(f"Failed to install {requirementname} module") from None


install_module("colorama~=0.4.6")
install_module("keystone-engine~=0.9.2")
install_module("capstone~=4.0.2")
"""
Ugh, keystone and capstone imports are ugly. There has to be a better way to do this...
"""
from keystone import Ks, KsError, KS_ARCH_ARM, KS_MODE_ARM, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from capstone import Cs, CsError, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import colorama

"""
Logging
"""


class LoggingLevel(Enum):
    Debug = 1
    Info = 2
    Important = 3
    VeryImportant = 4
    SuperImportant = 5
    Warning = 6


class Logging:

    def __init__(self, usedefaults=True, **kwargs) -> None:
        if usedefaults:
            self._fromoptions(colorized=True, printwarnings=True, printdebug=False, printinfo=True, printimportant=True,
                              printveryimportant=True, printsuperimportant=True, printspecial=True,
                              donotprintspecial=False, donotprintsuccessinfo=False, allowoverride=True, printall=True,
                              printnone=False)
        else:
            self._fromoptions(**kwargs)

    def _fromoptions(self, colorized=True, printwarnings=True, printdebug=False, printinfo=True, printimportant=True,
                     printveryimportant=True, printsuperimportant=True, printspecial=True, donotprintspecial=False,
                     donotprintsuccessinfo=False, allowoverride=True, printall=True, printnone=False) -> None:
        self.colorized = colorized
        self.printwarnings = printwarnings
        self.printdebug = printdebug
        self.printinfo = printinfo
        self.printimportant = printimportant
        self.printveryimportant = printveryimportant
        self.printsuperimportant = printsuperimportant
        self.printspecial = printspecial
        self.donotprintspecial = donotprintspecial
        self.donotprintsuccessinfo = donotprintsuccessinfo
        self.allowoverride = allowoverride
        self.printall = printall
        self.printnone = printnone
        self.Log = []

    def log(self, message: str, level: LoggingLevel = 2, override=False, successinfo=False, special=False):
        self.Log.append(message)
        if self.printnone:
            return
        if not (override and self.allowoverride):
            if successinfo and self.donotprintsuccessinfo:
                return
            if special and self.donotprintspecial:
                return
        if self.printall:
            toprint = True
        elif level == LoggingLevel.Debug and self.printdebug:
            toprint = True
        elif level == LoggingLevel.Info and self.printinfo:
            toprint = True
        elif level == LoggingLevel.Important and self.printimportant:
            toprint = True
        elif level == LoggingLevel.VeryImportant and self.printveryimportant:
            toprint = True
        elif level == LoggingLevel.SuperImportant and self.printsuperimportant:
            toprint = True
        elif special and self.printspecial:
            toprint = True
        else:
            toprint = False
        if toprint:
            self.printmessage(message, level, special, self.colorized)

    def printlog(self) -> None:
        print(self.Log)

    @staticmethod
    def printmessage(message: str, level: LoggingLevel, special, colorized):
        colors = {"Debug": "\033[0m", "Info": "\033[94m", "Important": "\033[95m", "VeryImportant": "\033[96m",
                  "SuperImportant": "\033[93m", "Warning": "\033[91m", "Special": "\033[92m", "reset": "\033[0m"}
        if colorized:
            if special:
                print(f"{colors['Special']}[{level.name}] [Special]: {message}{colors['reset']}")
            else:
                if level.name in colors:
                    print(f"{colors[level.name]}[{level.name}]: {message}{colors['reset']}")
                else:
                    print(f"[{level.name}]: {message}")
        else:
            if special:
                print(f"[{level.name}] [Special]: {message}")
            else:
                print(f"[{level.name}]: {message}")

    def warning(self, message: str, warningtype: BaseException = None):
        if warningtype:
            self.Log.append(f"[Warning]: {warningtype}: {message}")
            if self.printwarnings and _enabled and self.enabled:
                self.printmessage(f"{warningtype}: {message}", LoggingLevel.Warning, False, self.colorized)
        else:
            self.Log.append(f"[Warning]: {message}")
            if self.printwarnings and _enabled and self.enabled:
                self.printmessage(message, LoggingLevel.Warning, False, self.colorized)


colorama.just_fix_windows_console()
logging = Logging(usedefaults=True)

"""
Arm Hex Conversion
"""


class ArmHex:
    def __init__(self, arm64=False) -> None:
        self.arm64 = arm64
        self.architecture = "arm64" if arm64 else "arm"
        if self.arm64:
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def armtohex(self, armcode: str):
        try:
            """
            1. Assemble armcode to bytes with ks.asm, and grab the result (first item of tuple)
            2. Convert the list of encoded instructions to bytes
            3. Convert the bytes to a hex value
            4. Make the hex uppercase
            """
            return bytes(self.ks.asm(armcode)[0]).hex().upper()
        except KsError as e:
            # Todo: Error handling
            raise

    def hextoarm(self, hexcode: str, offset=0x0, delimiter: str = "\n"):
        """
        To-Do: Add documentation

        :raises ValueError: hexcode is not valid hex
        """
        if delimiter is None:
            delimiter = ""
        try:
            int(hexcode, 16)
        except ValueError:
            raise ValueError("hexcode is not a valid hex")
        try:
            """
            1. Convert hexcode to bytes (because capstone takes bytes, not hex)
            2. Disassemble hexcode to arm code with cs.dsm  
            3. Loop over all the disassembled instructions
            4. Get instruction as string using mnemonic and op_str attributes
            5. Concatenate list of instruction strings with delimiter
            """
            return delimiter.join([f"{instruction.mnemonic} {instruction.op_str}" for instruction in
                                   self.cs.disasm(bytes.fromhex(hexcode), offset)])
        except CsError as e:
            # Todo: Error handling
            raise


"""
Dumpcs Parsing
"""


def getactualdatatype(datatype: str) -> str:
    """
    Gets actual data type
    Removes modifiers and access modifiers
    """
    ...


def getmodifiers(datatype: str) -> list[str]:
    """
    Gets list of modifiers
    Removes actual data type and access modifiers
    """
    ...


def getmethodandclassfromoffset(offset: str) -> tuple[str, str]:
    """
    Gets the name of a method and the name of its class by the method offset

    :param offset: Offset of the method
    :return: Tuple with class name and method name: (classname, methodname)

    :raises ValueError: Method with this offset was not found in dumpcs
    """


def getfieldfromclassandoffset(classname: str, offset: str) -> str:
    """
    Gets the name of a field by the name of its class and the field offset

    :param classname: Name of the class the field is in
    :param offset: Offset of the field
    :return: Tuple with class name and method name: (classname, methodname)

    :raises ValueError: Class was not done
    :raises ValueError: Field with this offset was not found in class
    """


"""
Patches
"""


@dataclass
class Method:
    """
    :param classname: The name of the class the method is in
    :param name: The name of the method
    :param datatype: The data type of the method
    :param offset: The offset of the method
    """

    classname: str
    name: str
    datatype: str
    offset: str

@dataclass
class MethodParam:
    """
    :param paramnum: The number of the parameter in the method's parameter list (from 1 to # of parameters)
    """
    paramnum: int

    def __postinit__(self):
        if not isinstance(paramnum, int):
            raise TypeError("paramnum must be an integer")
        if paramnum <= 0:
            raise ValueError("paramnum must be at least 1 (corresponds to index of parameter in method)")

@dataclass
class Field:
    """
    :param classname: The name of the class the field is in
    :param name: The name of the field
    :param datatype: The data type of the field
    :param offset: The offset of the field. None if no offset.
    """

    classname: str
    name: str
    datatype: str
    offset: Optional[str] = None


class PatchType(Enum):
    """
    The type of data a patch is.
    If the patch is invalid for a field or method, the program will try to convert the patch value
    to another representation that means the same thing. If it fails to do so, it will throw an error and
    skip the method / field.
    . HexPatch: Arm instructions in hexadecimal representation. If used on a field, it
        will fail.
    . ArmPatch: Arm assembly code for 32bit (arm) or 64bit (arm64).
        Separate instructions with newlines or semicolons. If used on a field, it will fail.
    . NOPPatch: Use on void methods to make them do nothing. An example usage is implementing
        antiban by nopping a Ban method. When this type of patch is used, the patchto value does not matter.
        For consistency, I recommend setting patchto to None. If used on a field, it
        will fail.
    . IntPatch: Whole number. If patchto is a decimal number, the value will be
        rounded to the nearest whole number and a warning will be given. Works for int, char, float, double,
        byte, and boolean data types. If the value exceeds the integer limit of the data type of the method
        or field, it will fail. Can be negative, but if the data type of the method or field is unsigned,
        it will fail.
    . BoolPatch: True or False. Can be python built-in True or False.
        Can also be a string with the value of "true" or "false", which is not case-sensitive.
        Can also be 1 (true) or 0 (false).
    . FloatPatch: Whole number or decimal number. Works for both float
        and double data types. If the number cannot be represented, it will be rounded and a warning will
        be giveh. If the value exceeds the float / double limit of the data type of the method or field,
        it will fail. Also works for int, char, float, double, byte, and boolean data types if the value
        is a whole  number, though it is recommended to use Int instead of Float in this case.
        Can be negative, but if the data type of the method or field is unsigned, it will fail.
    . StringPatch: Text. If any of the characters in the string are not in the UTF-16 charset,
        it will fail. Also works for char data type if the value is only one character long.
    - CharPatch: Single character that is in the UTF-16 charset. Can be a unicode code point,
        a unicode sequence, or a one-character-long string.
        If it is a string that is shorter or longer than one character, it will fail. If it is a unicode
        code point or unicode sequence that is not in the UTF-16 charset, it will fail.
        Also works for string data type.
    """
    HexPatch = "HexPatch",
    ArmPatch = "ArmPatch",
    NOPPatch = "NOPPatch",
    IntPatch = "IntPatch",
    BoolPatch = "BoolPatch",
    FloatPatch = "FloatPatch",
    StringPatch = "StringPatch",
    CharPatch = "CharPatch",


Patch = TypeVar('Patch', bound='PatchBase')


# Sentinel value for empty patch data, for use in PatchBase class.
class _EmptyPatchData:
    pass


_emptypatchdata = _EmptyPatchData()


class PatchBase(ABC):

    # In the type hints for this function, we use union [Patch, None] rather than Optional[Patch] here because it
    # makes it explicit that None represents no value. This is necessary because for patchdata, _emptypatchdata
    # represents no value, not None.
    # noinspection PyProtectedMember
    def __init__(self, patchdata: Union[Any, _EmptyPatchData] = _emptypatchdata,
                 patch: Union[Patch, None] = None) -> None:
        """
        Attempts to create a Patch of this type from patch data or an existing Patch
        May do implicit conversions of the patch data

        Implementations of PatchBase SHOULD NOT OVERRIDE THIS METHOD. Instead, they should override the methods it
        internally uses: _frompatchdata, _frompatch, _fromnodata, _setupresources, and _cleanupresouces.

        :param patchdata: The patch data
        :param patch: The patch to create a new Patch from

        patchdata and patch are mutually exclusive; the caller may provide neither if this patch implements
        _fromnodata()

        :raises TypeError: Both patchdata and patch were provided - they are mutually exclusive
        :raises TypeError: Neither patchdata nor patch was provided and this patch does not implement _fromnodata()
        :raises ValueError: The Patch is invalid and cannot be created
        """
        if patchdata != _emptypatchdata and patch is not None:
            raise TypeError("patchdata and patch are mutually exclusive")
        if patchdata != _emptypatchdata:
            try:
                self._frompatchdata(patchdata)
            except ValueError:
                raise ValueError(f"{type(self).__name__} patch cannot be created from this data") from None
        elif patch is not None:
            try:
                self._frompatch(patch)
            except ValueError:
                raise ValueError(f"{type(patch).__name__} patch cannot be converted to"
                                 f" {type(self).__name__} patch") from None
        else:
            try:
                self._fromnodata()
            except ValueError:
                raise TypeError("This patch requires either patchdata or patch to be specified")
        #  We set the finalizer before calling _setupresources so if an exception occurs during
        #  _setupresources, _cleanupresources is still called.
        finalize(self, self._cleanupresources)
        self._setupresources()
        self.isinstantiated = True

    def _frompatchdata(self, patchdata: Any) -> None:
        """
        Attempts to create a new Patch of this type from the patch data
        Do not implement this method if a Patch of this type does not take any data.

        If the Patch is invalid and cannot be created, raises a ValueError

        :param patchdata: The patch data to create this patch with

        :raises ValueError: The Patch is invalid and cannot be created
        """
        raise ValueError

    def _frompatch(self, patch: Patch) -> None:
        """
        Attempts to create a Patch of this type from a Patch of another Patch type
        Do not implement this method if a Patch of this type cannot be created from another Patch type.

        If the Patch is invalid and cannot be created, raises a ValueError

        :param patch: The Patch to create a new Patch of this type from

        :raises ValueError: The Patch cannot be converted to this type of Patch
        """
        raise ValueError

    def _fromnodata(self) -> None:
        """
        Attempts to create a new Patch of this type without data.
        Do not implement this method if a Patch of this type cannot be created without data.

        If the Patch cannot be created without data, raises a ValueError

        :raises ValueError: The Patch cannot be created without data
        """
        raise ValueError

    def _setupresources(self) -> None:
        """
        Sets up any resources needed for the patch, such as loading a file

        Does not have to be implemented
        """
        pass

    def _cleanupresources(self) -> None:
        """
        Upon destruction, cleans up resources that the Patch loaded, created, or initialized

        Does not have to be implemented
        """
        pass

    @property
    @abstractmethod
    def requiredcode(self) -> Optional[list[str]]:
        """
        Code that is required to be added to the beginning of the script for this patch to work,
        such as functions or constants.
        These requirements will be added to the beginning of the script. Order is not guaranteed, so
        requirements that requires other requirements should have those requirements built-in.

        Make sure requirements do not conflict with each other - for instance, two requirements should
        not set a global variable with the same name. The best way to avoid conflicts is to wrap everything
        in one top-level table. A great example of this is HTCheater's Il2CppExplorer
        (https://github.com/HTCheater/Il2CppExplorer/blob/main/Il2CppExplorer.lua)

        Each requirement should be an element in the list. However, if two things are associated (such as a
        function that calls another function), you can specify them as one element.
        Whether methods or fields are patched is not checked, so specify requirements for
        both methods and fields.

        This is much cleaner than adding these requirements to the beginning of the patch code itself.
        Also, it minimizes duplicated code.
        """
        # Implementation for requirements: Store set (no duplicates) of requirements; after patch code is done
        # generating, insert requirements at beginning of generated script
        # Make sure to insert trailing and leading whitespace for each requirement, but only if it's not already there
        raise NotImplementedError

    @property
    @abstractmethod
    def canpatchmethods(self) -> bool:
        """
        Whether this patch can be used on methods

        Even if this is True, the patch still may not work on some methods due to factors like data types.
        Data types can be checked with supportsdatatype. For other factors, an error will be raised when
        patchmethod is called.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def canpatchfields(self) -> bool:
        """
        Whether this patch can be used on fields

        Even if this is True, the patch still may not work on some fields due to factors like data types.
        Data types can be checked with supportsdatatype. For other factors, an error will be raised when
        patchfield is called.
        """
        raise NotImplementedError

    @abstractmethod
    def supportsdatatype(self, datatype: str) -> bool:
        """
        Whether this patch can be used on methods / fields of this data type, taking into account the type of the
        patchdata. To be used alongside canpatchmethods / canpatchfields.
        """
        raise NotImplementedError

    def patchmethod(self, method: Method) -> str:
        """
        This method does the actual work of generating the patch code
        Patches a method. Make sure to call canpatchfield() and supportsdatatype() first, to avoid errors.

        The patch code does not have to be a standalone script, but it does have to guarantee
        that it will not cause conflicts or issues with code from other patches

        :param method: The method to patch
        :return: The generated code that patches the method

        :raises ValueError: The patch does not work on methods
        :raises ValueError: The patch does not work on methods of this data type

        Does not have to be implemented
        """
        raise NotImplementedError(f"{type(self).__name__} patch does not work on methods")

    def patchfield(self, field: Field) -> str:
        """
        This method does the actual work of generating the patch code
        Patches a field. Make sure to call canpatchfield() and supportsdatatype() first, to avoid errors.

        The patch code does not have to be a standalone script, but it does have to guarantee
        that it will not cause conflicts or issues with code from other patches

        :param field: The field to patch
        :return: The generated code that patches the field

        :raises ValueError: The patch does not work on fields
        :raises ValueError: The patch does not work on fields of this data type

        Does not have to be implemented
        """
        raise NotImplementedError(f"{type(self).__name__} patch does not work on fields")


class HexPatch(PatchBase):
    patchids: List[str] = []

    def _frompatchdata(self, patchdata: Any) -> None:
        if patchdata is None:
            raise ValueError("Expected hex to patch to, got None")
        if not isinstance(patchdata, (str, int)):
            raise ValueError(f"Expected hex as str or int, got data of type {type(patchdata).__name__}")
        if isinstance(patchdata, int):
            patchdata = str(patchdata)
        # Remove 0x prefix
        if patchdata.startswith("0x"):
            patchdata = patchdata[2:]
        # Remove whitespace
        patchdata = re.sub(r"\s", "", patchdata)
        # Check that hex is valid
        try:
            int(patchdata, 16)
        except ValueError:
            raise ValueError(f"patchdata is not a valid hex")
        self.newhex: str = patchdata

    def _frompatch(self, patchtype: PatchType, patch: Patch) -> None:
        raise NotImplementedError
        match patchtype:
            case PatchType.NOPPatch:
                raise NotImplementedError  # Fixme
            case PatchType.ArmPatch:
                raise NotImplementedError  # Fixme
            case _:
                raise ValueError

    @property
    def requiredcode(self) -> Optional[list[str]]:
        return ["""-- Memory patch functions by geokar2006 - \
https://github.com/geokar2006/Game-Guardian-Easy-MemoryPatch
local function MemoryPatch(a,b,c)local d,e,f,g,h,j='',false,false,{},{},0;local function k(a)return#a>0 and 
a:lower():find("[^%dabcdef]")==nil;end;local function l(a,b)local r=''local function f(v)v=string.format(
"%X",v)if#v==1 then return"0"..v;end;return v;end;for i=0,b-1 do r=r..f(gg.getValues({{address=a+i,
flags=gg.TYPE_BYTE}})[1].value)end;return r;end;local function m(a)local r = ''if#a==0 then return false;end;for i=1,
#a,2 do r=r..a:sub(i,i+1)end;return r:upper()end;local function n(a,b)local r,i={},0;for v in a:gmatch("%S%S")do table.insert(r,{address=b+i,flags=gg.TYPE_BYTE,value=v.."r"})i=i+1;end;return r;end;local o={Modify=function()if e and not f then gg.setValues(g)f=true;return true;end;return false;end,Restore=function()if e and f then gg.setValues(h)f=false;return true;end;return false;end,GetInfo=function()return{ok=e,lib=a,offset=string.format("0x%X",j).." + "..string.format("0x%X",b),hex=c,originalHex=d}end,IsModified=function()return f;end}c=c:gsub(" ", ""):gsub("0x", ""):upper()if not k(c)then print("[MemoryPatch] Hex is wrong for "..o.GetInfo())return o;end;for _,v in ipairs(gg.getRangesList(a)) do if v.type=="r-xp"or v.state=="Xa"then j=v.start;e=true;break;end;end;if not e then print("[MemoryPatch] Lib not found for "..o.GetInfo())return o;end;d=m(l(j+b,(#c+#c%2)/2))if #c<#d then c=c..d:sub(#d)end;g=n(c,j+b)h=n(d,j+b)return o;end"""
                # noqa: E501
                ]

    @property
    def canpatchmethods(self) -> bool:
        return True

    @property
    def canpatchfields(self) -> bool:
        return False

    def supportsdatatype(self, datatype: str) -> bool:
        """ This depends on the asm code patchdata represents. Though this may fail, we will let it crash,
        as the patch technically works - the provided hex is just incorrect, which we can't do much about unless you
        want to somehow analyze it."""
        return True

    def patchmethod(self, method: Method) -> str:
        patchid = f"hexpatch_{method.classname}_{method.name}_{method.offset}"  # Unique patchid
        self.patchids.append(patchid)
        return f"-- Hex patch method {method.classname}.{method.name} at offset {method.offset} to hex " \
               f"{self._formathex(self.newhex)}" \
               f"\n{patchid} = MemoryPatch(\"libil2cpp.so\", \"{method.offset}\", \"{self.newhex}\")\n" \
               f"{patchid}.Modify()"""

    @staticmethod
    def _formathex(hexstring: str) -> str:
        """
        This is a lot of annoying work to add some damn spaces between letters, so I crammed it all into one function
        to save space. As all good programmers should.
        """

        def remove_whitespace(s: str) -> str:
            return "".join(s.split())

        def wraptext(s: str, size: int) -> list[str]:
            # Thanks to https://stackoverflow.com/questions/9475241/split-string-every-nth-character
            return [s[i:i + size] for i in range(0, len(s), size)]

        hexstring = remove_whitespace(hexstring)
        assert len(hexstring) % 2 == 0, "Invalid hex string (odd length)"
        return " ".join(wraptext(hexstring, 2))


class ArmPatch(PatchBase):
    ...


class NOPPatch(PatchBase):
    patchids: List[str] = []

    def _fromnodata(self) -> None:
        match architecture.lower().strip():
            case "32bit":
                armhex: ArmHex = ArmHex(False)
            case "64bit":
                armhex: ArmHex = ArmHex(True)
            case _:
                raise ValueError(f"Invalid architecture: {architecture} (valid architectures are '32bit' and '64bit'")
        self.newhex: str = armhex.armtohex("NOP")

    @property
    def requiredcode(self) -> Optional[list[str]]:
        return ["""-- Memory patch functions by geokar2006 - \
    https://github.com/geokar2006/Game-Guardian-Easy-MemoryPatch
    local function MemoryPatch(a,b,c)local d,e,f,g,h,j='',false,false,{},{},0;local function k(a)return#a>0 and 
    a:lower():find("[^%dabcdef]")==nil;end;local function l(a,b)local r=''local function f(v)v=string.format(
    "%X",v)if#v==1 then return"0"..v;end;return v;end;for i=0,b-1 do r=r..f(gg.getValues({{address=a+i,
    flags=gg.TYPE_BYTE}})[1].value)end;return r;end;local function m(a)local r = ''if#a==0 then return false;end;for i=1,
    #a,2 do r=r..a:sub(i,i+1)end;return r:upper()end;local function n(a,b)local r,i={},0;for v in a:gmatch("%S%S")do table.insert(r,{address=b+i,flags=gg.TYPE_BYTE,value=v.."r"})i=i+1;end;return r;end;local o={Modify=function()if e and not f then gg.setValues(g)f=true;return true;end;return false;end,Restore=function()if e and f then gg.setValues(h)f=false;return true;end;return false;end,GetInfo=function()return{ok=e,lib=a,offset=string.format("0x%X",j).." + "..string.format("0x%X",b),hex=c,originalHex=d}end,IsModified=function()return f;end}c=c:gsub(" ", ""):gsub("0x", ""):upper()if not k(c)then print("[MemoryPatch] Hex is wrong for "..o.GetInfo())return o;end;for _,v in ipairs(gg.getRangesList(a)) do if v.type=="r-xp"or v.state=="Xa"then j=v.start;e=true;break;end;end;if not e then print("[MemoryPatch] Lib not found for "..o.GetInfo())return o;end;d=m(l(j+b,(#c+#c%2)/2))if #c<#d then c=c..d:sub(#d)end;g=n(c,j+b)h=n(d,j+b)return o;end"""
                # noqa: E501
                ]

    @property
    def canpatchmethods(self) -> bool:
        return True

    @property
    def canpatchfields(self) -> bool:
        return False

    def supportsdatatype(self, datatype: str) -> bool:
        """ You can only NOP voids, or the code will crash due to lack of a return value. """
        return datatype == "void"

    def patchmethod(self, method: Method) -> str:
        patchid = f"hexpatch_{method.classname}_{method.name}_{method.offset}"  # Unique patchid
        self.patchids.append(patchid)
        return f"-- NOP method {method.classname}.{method.name} at offset {method.offset} (hex patch to hex " \
               f"{self._formathex(self.newhex)})" \
               f"\n{patchid} = MemoryPatch(\"libil2cpp.so\", \"{method.offset}\", \"{self.newhex}\")\n" \
               f"{patchid}.Modify()"""

    @staticmethod
    def _formathex(hexstring: str) -> str:
        """
        This is a lot of annoying work to add some damn spaces between letters, so I crammed it all into one function
        to save space. As all good programmers should.
        """

        def remove_whitespace(s: str) -> str:
            return "".join(s.split())

        def wraptext(s: str, size: int) -> list[str]:
            # Thanks to https://stackoverflow.com/questions/9475241/split-string-every-nth-character
            return [s[i:i + size] for i in range(0, len(s), size)]

        hexstring = remove_whitespace(hexstring)
        assert len(hexstring) % 2 == 0, "Invalid hex string (odd length)"
        return " ".join(wraptext(hexstring, 2))


class IntPatch(PatchBase):
    ...


class FloatPatch(PatchBase):
    """
    Stored as float. When patching, rounds and converts to string using f"{VALUE:.PRECISIONf}"
    """
    ...


class BoolPatch(PatchBase):
    ...


class StringPatch(PatchBase):
    ...


class CharPatch(PatchBase):
    """
    Stored as string. When patching, converts to integer using ord(VALUE)
    """
    ...


def isvalididentifier(identifier: str) -> bool:
    raise NotImplementedError


class MethodPatch:

    def __init__(self, patch: Patch, method: Method):
        self.patchtype: PatchType = PatchType[type(patch).__name__]

        if not patch.canpatchmethods:
            raise ValueError(f"{self.patchtype.value} patch does not support methods")
        if not patch.supportsdatatype(method.datatype):
            raise ValueError(f"{self.patchtype.value} patch with data {patch.patchdata} does not support methods of"
                             f" type {method.datatype}")
        if not isvalididentifier(method.classname):
            raise ValueError(f"Method's class name ({method.classname}) is not valid")
        if not isvalididentifier(method.name):
            raise ValueError(f"Method's name ({method.name}) is not valid")
        if not method.offset.startswith("0x"):
            method.offset = f"0x{method.offset}"
        try:
            int(method.offset, 16)
        except ValueError:
            f"{method.offset} is not a valid offset"

        self.patch: Patch = patch
        self.method: Method = method

    def makepatch(self) -> str:
        return self.patch.patchmethod(self.method)


class FieldPatch:

    def __init__(self, patch: Patch, field: Field):
        self.patchtype: PatchType = PatchType[type(patch).__name__]

        if not patch.canpatchfields:
            raise ValueError(f"{self.patchtype.value} patch does not support fields")
        if not patch.supportsdatatype(field.datatype):
            raise ValueError(f"{self.patchtype.value} patch with data {patch.patchdata} does not support fields of"
                             f" type {field.datatype}")
        if not isvalididentifier(field.classname):
            raise ValueError(f"Field's class name ({field.classname}) is not valid")
        if not isvalididentifier(field.name):
            raise ValueError(f"Field's name ({field.name}) is not valid")
        if field.offset is not None:
            if not field.offset.startswith("0x"):
                field.offset = f"0x{field.offset}"
            try:
                int(field.offset, 16)
            except ValueError:
                f"{field.offset} is not a valid offset"

        self.patch: Patch = patch
        self.field: Field = field

    def makepatch(self) -> str:
        return self.patch.patchfield(self.field)


"""
Building Script
"""


class Script:

    def __init__(self):
        self.code = ""

    @staticmethod
    def _escapestring(s: str) -> str:
        return s.replace('\\', '\\\\').replace("\"", "\\\"")

    @staticmethod
    def _list_items(items: Union[Sequence[str], set[str]]) -> str:
        """
        Helper function to convert a list of items to a grammatically correct string
        """
        if not isinstance(items, Union[tuple, list]):
            logging.log(f"_list_items() function called on object of type {type(items).__name__}"
                        f", which is unordered.", LoggingLevel.Debug)
        if len(items) == 1:
            return str(items[0])
        elif len(items) == 2:
            return str(items[0]) + " and " + str(items[1])
        else:
            result = ""
            for i in range(len(items) - 1):
                result += str(items[i]) + ", "
            result += "and " + str(items[-1])
            return result

    def addopeningcomment(self, scripttitle: str, scriptdescription: Optional[str], scriptauthor: Optional[str],
                          gamename: str, gameversion: str, architecture: str) -> None:
        self.code += f"--[[\n\n{self._escapestring(scripttitle)}"
        if scriptauthor is not None:
            self.code += f" by {self._escapestring(scriptauthor)}"
        self.code += f"\nFor {self._escapestring(gamename)} version {self._escapestring(gameversion)}" \
                     f" (only works on {self._escapestring(architecture)} devices)"""
        if scriptdescription is not None:
            self.code += f"{self._escapestring(scriptdescription)}"
        self.code += "\n\nScript generated by Il2cppPatch - https://github.com/HorridModz/Il2cppPatch\n\n--]]\n\n"

    def addalert(self, alert: str) -> None:
        self.code += f"""gg.alert("{self._escapestring(alert)}")"""

    def addtoast(self, toast: str) -> None:
        self.code += f"""gg.toast("{self._escapestring(toast)}")"""

    def addarchitecturecheck(self, architecture: str) -> None:
        match architecture.lower().strip():
            case "32bit":
                self.require32bit()
            case "64bit":
                self.require64bit()
            case _:
                raise ValueError(f"Invalid architecture: {architecture} (valid architectures are '32bit' and '64bit'")

    def require32bit(self) -> None:
        self.code += r"""if gg.getTargetInfo().x64 then
    print("Sorry, this script is only for 32bit devices.")
    os.exit()
    """

    def require64bit(self) -> None:
        self.code += r"""if not gg.getTargetInfo().x64 then
    print("Sorry, this script is only for 64bit devices.")
    os.exit()
    """

    def _addpatchrequirements(self, patches: List[MethodPatch | FieldPatch]) -> None:
        # Build dict of patch types and what code they require
        patchtyperequirements: dict[PatchType, list[str]] = {}
        for patch in patches:
            if patch.patchtype not in patchtyperequirements and patch.patch.requiredcode:
                patchtyperequirements[patch.patchtype] = patch.patch.requiredcode
        # Using the previous index, build list of required code snippets and what patches require them
        requirements: Dict[str, List[PatchType]] = {}
        for patchtype, codesnippets in patchtyperequirements.items():
            for codesnippet in codesnippets:
                if codesnippet in requirements:
                    requirements[codesnippet].append(patchtype)
                else:
                    requirements[codesnippet] = [patchtype]
        # Build scripts now that we have an index of required code snippets
        self.code += "\n--[[ Needed Functions and Utilities --]]\n\n"
        for code, requiredby in requirements.items():
            self.code += f"-- Required by patches: {self._list_items([patchtype.value[0] for patchtype in requiredby])}\n"
            self.code += f"{code}\n"

    def addpatches(self, patchestoadd: List[MethodPatch | FieldPatch]) -> None:
        """ ONLY meant to be called at the end, after all editing is done. If you call it twice, the patches'
        requirements will be added multiple times, which will clutter the script. Instead, keep track of all the 
        patches you want to add and call this method once you are finished."""
        self._addpatchrequirements(patchestoadd)
        self.code += "\n--[[ Main Code --]]\n"
        for patch in patchestoadd:
            self.code += f"\n{patch.makepatch()}\n"


"""
Main Code
"""

if __name__ == "__main__":
    global patches
    # noinspection PyRedeclaration
    patches: List[MethodPatch | FieldPatch] = []
    main()
