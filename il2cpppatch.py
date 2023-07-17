def config():
    """
    Change these values to generate your script!
    """

    """
    Path to the dumpcs file
    Make sure not to remove the r before the opening quotation mark!
    """
    dumpcspath = r"C:\Users\zachy\OneDrive\Documents\Work\Projects\Pixel Gun 3D\Pixel Gun 3D 22.6.0\Pixel Gun 3D 22.6.0 dump.cs"
    """
    Path to the .so library file (usually libil2cpp.so)
    Make sure not to remove the r before the opening quotation mark!
    """
    libpath = r"C:\Users\zachy\OneDrive\Documents\Work\Projects\Pixel Gun 3D\Pixel Gun 3D 22.6.0\libil2cpp.so"
    """
    Path to the output script file
    Make sure not to remove the r before the opening quotation mark!
    """
    outputpath = r"C:\Users\zachy\OneDrive\Documents\Work\Projects\Pixel Gun 3D\Pixel Gun 3D 22.6.0\il2cpppatchoutput.lua"

    """
    Settings for generated script
    
    scripttitle: Title of the script.
    scriptauthor: Your name. To make it anonymous, set to None.
    scriptdescription: Description of what the script does. To not have a description, set to None.
    """
    scripttitle = "Il2cpp Patch Output"
    scriptdescription = None
    scriptauthor = "User123456789#6424"

    """
    Game info
    
    gamename: Name of the game the script is for.
    gameversion: Game version the script is for.
    require632it: If True, requires 32bit. If require32bit and require64bit are both False, works for
    both 32bit and and 64bit. False is recommended.
    require64bit: If True, requires 64bit. If require32bit and require64bit are both False, works for
    both 32bit and and 64bit. False is recommended.
    """
    gamename = "Pixel Gun 3D"
    gameversion = "22.6.0"
    require32bit = False
    require64bit = False

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
    offset: Offset of the field
    
    Use it in place of classname and fieldname, with * at the beginning, like this:
    *getfieldfromclassandoffset(offset)
    
    For example:
    
    patchfield(*getmethodandclassfromoffset("MyClass", 0x69), 69, "int") 
    
    Patchmethod: Function to patch one method.

    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the method is in.
    methodname: Name of the method to patch.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.

    Patchfield: Function to patch one field.

    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the method is in.
    fieldname: Name of the field to patch.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    
    Patchall: Function to patch all methods / fields in a class.
    
    Arguments:
    
    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class to patch.
    namecontains: Only patch methods / fields that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    patchmethods: Whether or not to patch methods
    patchfields: Whether or not to patch fields
    datatype: Only patch methods / fields that are of this data type. Can include modifiers, such
        as static, and access modifiers, such as public.
        This is not case sensitive.
        Examples: int, static void, public Dictionary<string, SaltedInt> 
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    
    Restoremethod: Function to revert patched method back to original
    
    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the method is in.
    methodname: Name of the method to restore.
    
    Restorefield: Function to revert patched field back to original value
    
    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the field is in.
    methodname: Name of the field to restore.
    
    Restoreallinclass: Function to revert all patched methods / fields in a class
 
    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class to revert methods / fields in.
    restoremethods: Whether or not to restore methods
    restorefields: Whether or not to restore fields
    
    Restoreall: Function to revert all patched methods / fields in all classes
 
    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    restoremethods: Whether or not to restore methods
    restorefields: Whether or not to restore fields
    
    Callmethod: Function to call one method
    
    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the method is in.
    methodname: Name of the method to call.
    params: List of parameters to call the method with, in this format: datatype value
            Only parameters
            If a parameter's value is null, the data type may optionally be None (without quotes) or "null",
            rather than the actual data type of the parameter in the method signature
            Only supports primitive types. Does not support nullable types, either.
            Examples: "int": 1, "string": "hello", None: "null", "null": "null"
            If there are no parameters, pass an empty list or None.
            Params much match method's signature (it will also work if convertparams is true
            and the params can be converted to match the signature).
    times: Number of times to call the method. Must be greater than 0.
    delaymillisecs: The delay (in milliseconds) between calling the method. Only matters if times is
            greater than 1. Set to 0 or None to have no delay. Defaults to None (no delay).
            This delay will not apply before the first call(s) or after the last call(s), just in between.
    convertparams: Whether to attempt to convert parameters to other data types in order to match
        the method's signature.
    
    Callall: Function to call all methods in a class.
    
    Arguments:
    
    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class to call the methods from.
    namecontains: Only call methods that contain this substring in their name.
        This is not case sensitive. To disable, set to None.
    datatype: Only call methods that are of this data type. Can include modifiers, such
        as static, and access modifiers, such as public.
        This is not case sensitive.
        Examples: int, static void, public Dictionary<string, SaltedInt> 
    params: Dictionary of parameters to call the method with, in this format: "data type": value
            If the value is null, the data type should be None (without quotes) or "null"
            Only supports primitive types. Does not support nullable types, either.
            Examples: "int": 1, "string": "hello", None: "null", "null": "null"
            Only calls methods that follow this signature of params (or if convertparams is true
            and the params can be converted to match the signature).
    times: Number of times to call the methods. Must be greater than 0.
    delaymillisecs: The delay (in milliseconds) between calling methods. Only matters if times is greater than 1. 
        Set to 0 or None to have no delay. Defaults to None (no delay).
        This delay will not apply before the first 
        call(s) or after the last call(s), just in between.
    convertparams: Whether to attempt to convert parameters to other data types in order to match method
        signatures.
    """


    """
    Patchtype:
    
    The type of data a patch is.
    If the patch is invalid for a field or method, the program will try to convert the patch value
    to another representation that means the same thing. If it fails to do so, it will throw an error and
    skip the method / field.
    . Hex / HexPatch / HexInstruction(s): Arm instructions in hexadecimal representation. If used on a field, it
        will fail.
    . Arm / ArmPatch / ArmInstruction(s): Arm assembly code for 32bit (arm) or 64bit (arm64).
        Separate instructions with newlines or semicolons. If used on a field, it will fail.
    . Nop / NopPatch / NOP / NOPPatch: Use on void methods to make them do nothing. An example usage is implementing
        antiban by nopping a Ban method. When this type of patch is used, the patchto value does not matter.
        For consistency, I recommend setting patchto to None. If used on a field, it
        will fail.
    . Int / IntPatch / Integer / IntegerPatch: Whole number. If patchto is a decimal number, the value will be
        rounded to the nearest whole number and a warning will be given. Works for int, char, float, double,
        byte, and boolean data types. If the value exceeds the integer limit of the data type of the method
        or field, it will fail. Can be negative, but if the data type of the method or field is unsigned,
        it will fail.
    . Bool / BoolPatch / Boolean / BooleanPatch: True or False. Can be python built-in True or False.
        Can also be a string with the value of "true" or "false", which is not case-sensitive.
        Can also be 1 (true) or 0 (false).
    . Float / FloatPatch / Double / DoublePatch: Whole number or decimal number. Works for both float
        and double data types. If the number cannot be represented, it will be rounded and a warning will
        be giveh. If the value exceeds the float / double limit of the data type of the method or field,
        it will fail. Also works for int, char, float, double, byte, and boolean data types if the value
        is a whole  number, though it is recommended to use Int instead of Float in this case.
        Can be negative, but if the data type of the method or field is unsigned, it will fail.
    . String / StringPatch: Text. If any of the characters in the string are not in the UTF-16 charset,
        it will fail. Also works for char data type if the value is only one character long.
    - Char / Character: Single character that is in the UTF-16 charset. Can be a unicode code point,
        a unicode sequence, or a one-character-long string.
        If it is a string that is shorter or longer than one character, it will fail. If it is a unicode
        code point or unicode sequence that is not in the UTF-16 charset, it will fail.
        Also works for string data type.
    """
    patchall(classname="WeaponSounds", namecontains="Ban", patchmethods=True, patchfields=True, datatype="void",
             patchto=1, patchtype=PatchType.NOP)


"""
Everything below here is the code that makes it work - you don't need to look at this!
It's all in one file, so the code is kind of cluttered and messy.
"""


def patchall():
    """
    Patches all methods, fields, or both in an entire class.

    Classname inference: Last classname that was passed in (fails if first call)
    Namecontains inference: Defaults to None
    Patchmethods inference: Last patchmethods that was passed in (defaults to true if first call)
    Patchfields inference: Last patchfields that was passed in (defaults to true if first call)
    Datatype inference: Last datatype that was passed in (defaults to None if first call)
    Patchto inference: Fails
    Patchtype inference: Tries to choose a type that is compatible with the patchto value. Fails
        if the patchto value is also not specified, or if there is no compatible type
    """


def patchmethod():
    """
    Patches a single method.

    Classname inference: Last classname that was passed in (fails if first call)
    Methodname inference: Fails
    Datatype inference: Last datatype that was passed in (defaults to None if first call)
    Patchto inference: Fails
    Patchtype inference: Tries to choose a type that is compatible with the patchto value. Fails
        if the patchto value is also not specified, or if there is no compatible type
    """


def patchfield():
    """
    Patches a single field.

    Classname inference: Last classname that was passed in (fails if first call)
    Fieldname inference: Fails
    Datatype inference: Last datatype that was passed in (defaults to None if first call)
    Patchto inference: Fails
    Patchtype inference: Tries to choose a type that is compatible with the patchto value. Fails
        if the patchto value is also not specified, or if there is no compatible type
    """


def callall():
    """
    Calls all methods in an entire class.

    Classname inference: Last classname that was passed in (fails if first call)
    Namecontains inference: Defaults to None
    Datatype inference: Last datatype that was passed in (defaults to None if first call)
    Params inference: {}
    """


"""
Requiring python 3.11 or later
"""
import sys

# From https://stackoverflow.com/a/34911547/20558255
if sys.version_info < (3, 11):
    # noinspection PyStringFormat
    sys.exit("""Python 3.11 or later is required. You currently have Python %s.%s installed.
Download the latest version of Python from https://www.python.org/downloads/"""
             % sys.version_info[:2])

"""
Installing and importing modules
"""
from typing import Any, Optional, Union, TypeVar, overload
import os
import importlib
import pkg_resources
import subprocess
import re
import json
from weakref import finalize
from enum import Enum
from abc import ABC, abstractmethod


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
            self._fromoptions(colorized=True,
                              printwarnings=True,
                              printdebug=False,
                              printinfo=True,
                              printimportant=True,
                              printveryimportant=True,
                              printsuperimportant=True,
                              printspecial=True,
                              donotprintspecial=False,
                              donotprintsuccessinfo=False,
                              allowoverride=True,
                              printall=True,
                              printnone=False
                              )
        else:
            self._fromoptions(**kwargs)

    def _fromoptions(self,
                     colorized=True,
                     printwarnings=True,
                     printdebug=False,
                     printinfo=True,
                     printimportant=True,
                     printveryimportant=True,
                     printsuperimportant=True,
                     printspecial=True,
                     donotprintspecial=False,
                     donotprintsuccessinfo=False,
                     allowoverride=True,
                     printall=True,
                     printnone=False
                     ) -> None:
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
        colors = {
            "Debug": "\033[0m",
            "Info": "\033[94m",
            "Important": "\033[95m",
            "VeryImportant": "\033[96m",
            "SuperImportant": "\033[93m",
            "Warning": "\033[91m",
            "Special": "\033[92m",
            "reset": "\033[0m"
        }
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
            # To-Do: Error handling
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
            return delimiter.join([f"{instruction.mnemonic} {instruction.op_str}"
                                   for instruction in self.cs.disasm(bytes.fromhex(hexcode), offset)])
        except CsError as e:
            # To-Do: Error handling
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


class PatchType(Enum):
    """
    The type of data a patch is.
    If the patch is invalid for a field or method, the program will try to convert the patch value
    to another representation that means the same thing. If it fails to do so, it will throw an error and
    skip the method / field.
    . Hex / HexPatch / HexInstruction(s): Arm instructions in hexadecimal representation. If used on a field, it
        will fail.
    . Arm / ArmPatch / ArmInstruction(s): Arm assembly code for 32bit (arm) or 64bit (arm64).
        Separate instructions with newlines or semicolons. If used on a field, it will fail.
    . Nop / NopPatch / NOP / NOPPatch: Use on void methods to make them do nothing. An example usage is implementing
        antiban by nopping a Ban method. When this type of patch is used, the patchto value does not matter.
        For consistency, I recommend setting patchto to None. If used on a field, it
        will fail.
    . Int / IntPatch / Integer / IntegerPatch: Whole number. If patchto is a decimal number, the value will be
        rounded to the nearest whole number and a warning will be given. Works for int, char, float, double,
        byte, and boolean data types. If the value exceeds the integer limit of the data type of the method
        or field, it will fail. Can be negative, but if the data type of the method or field is unsigned,
        it will fail.
    . Bool / BoolPatch / Boolean / BooleanPatch: True or False. Can be python built-in True or False.
        Can also be a string with the value of "true" or "false", which is not case-sensitive.
        Can also be 1 (true) or 0 (false).
    . Float / FloatPatch / Double / DoublePatch: Whole number or decimal number. Works for both float
        and double data types. If the number cannot be represented, it will be rounded and a warning will
        be giveh. If the value exceeds the float / double limit of the data type of the method or field,
        it will fail. Also works for int, char, float, double, byte, and boolean data types if the value
        is a whole  number, though it is recommended to use Int instead of Float in this case.
        Can be negative, but if the data type of the method or field is unsigned, it will fail.
    . String / StringPatch: Text. If any of the characters in the string are not in the UTF-16 charset,
        it will fail. Also works for char data type if the value is only one character long.
    - Char / Character: Single character that is in the UTF-16 charset. Can be a unicode code point,
        a unicode sequence, or a one-character-long string.
        If it is a string that is shorter or longer than one character, it will fail. If it is a unicode
        code point or unicode sequence that is not in the UTF-16 charset, it will fail.
        Also works for string data type.
    """
    HexPatch = "HexPatch",
    Hex = "HexPatch",
    HexInstruction = "HexPatch",
    HexInstructions = "HexPatch",
    ArmPatch = "ArmPatch",
    Arm = "ArmPatch",
    ArmInstruction = "ArmPatch",
    ArmInstructions = "ArmPatch",
    NopPatch = "NopPatch",
    NOPPatch = "NopPatch",
    Nop = "NopPatch",
    NOP = "NopPatch",
    IntPatch = "IntPatch",
    IntegerPatch = "IntPatch",
    Int = "IntPatch",
    Integer = "IntPatch",
    BoolPatch = "BoolPatch",
    BooleanPatch = "BoolPatch",
    Bool = "BoolPatch",
    Boolean = "BoolPatch",
    FloatPatch = "FloatPatch",
    DoublePatch = "FloatPatch",
    Float = "FloatPatch",
    Double = "FloatPatch",
    StringPatch = "StringPatch",
    String = "StringPatch",
    Text = "StringPatch",
    CharPatch = "CharPatch",
    CharacterPatch = "CharPatch",
    Char = "CharPatch",
    Character = "CharPatch",


PatchImplementation = TypeVar('PatchImplementation', bound='Patch')

# Sentinel value for empty patch data
_emptypatchdata = object()


# WHY IS THIS HERE no|inspection PyUnusedLocal
class Patch(ABC):

    @overload
    def __init__(self, patchdata: Any) -> None:
        pass

    @overload
    def __init__(self, patch: PatchImplementation) -> None:
        pass

    # In the type hints, we use union [Patch, None] rather than Optional[Patch] here because it makes it
    # explicit that None represents no value. This is necessary because for patchdata, _emptypatchdata
    # represents no value, not None.
    def __init__(self, patchdata: Union[Any, type('_emptypatchdata')] = _emptypatchdata,
                 patch: Union[PatchImplementation, None] = None) -> None:
        """
        Attempts to create a Patch of this type from patch data or an existing Patch
        May do implicit conversions of the patch data

        If the Patch is invalid and cannot be created, raises NotImplementedError
        and stores the reason why it is invalid in the invalidpatchreason field.

        Implementations of Patch should not override this method. Instead, they should override
        the methods it internally uses: _frompatchdata, _frompatch, _setupresources, and _cleanupresoucres.

        :param patchdata: The patch data
        :param patch: The patch to create a new Patch from

        patchdata and patch are mutually exclusive and jointly exhaustive

        :raises TypeError: Both patchdata and patch were provided - they are mutually exclusive
        :raises TypeError: Neither patchdata nor patch was provided - they are jointly exhaustive
        :raises NotImplementedError: The Patch is invalid and cannot be created
        """
        self.invalidpatchreason: Optional[str] = None
        if patchdata != _emptypatchdata and patch is not None:
            raise TypeError("patchdata and patch are mutually exclusive")
        if patchdata != _emptypatchdata:
            try:
                self._frompatchdata(patchdata)
            except ValueError as e:
                if str(e):
                    self.invalidpatchreason = str(e)
                else:
                    self.invalidpatchreason = f"{type(self).__name__} patch cannot be created from this data."
                raise NotImplementedError(f"{type(self).__name__} patch cannot be created from this data.")
        elif patch is not None:
            patchtype = PatchType[type(patch).__name__]
            try:
                self._frompatch(patchtype, patch)
            except ValueError:
                self.invalidpatchreason = (f"{type(patch).__name__} patch cannot be converted to"
                                           f" {type(self).__name__} patch.")
                raise NotImplementedError(f"{type(patch).__name__} patch cannot be converted to"
                                          f" {type(self).__name__} patch.")
        else:
            raise TypeError("patchdata and patch are jointly exhaustive")
        #  We set the finalizer before calling _setupresources so if an exception occurs during
        #  _setupresources, _cleanupresources is still called.
        finalize(self, self._cleanupresources)
        self._setupresources()

    @abstractmethod
    def _frompatchdata(self, patchdata: Any) -> None:
        """
        Attempts to create a new Patch of this type from the patch data

        If the Patch is invalid and cannot be created, raises an empty ValueError

        :param patchdata: The patch data

        :raises ValueError: The Patch is invalid and cannot be created
        """
        raise NotImplementedError

    @abstractmethod
    def _frompatch(self, patchtype: PatchType, patch: PatchImplementation) -> None:
        """
        Attempts to create a Patch of this type from a Patch of another Patch type

        If the Patch is invalid and cannot be created, raises a ValueError with the reason why

        :param patchtype: The type of the Patch to create a new Patch from
        :param patch: The patch to create a new Patch from

        :raises ValueError: The Patch is invalid and cannot be created
        """
        raise NotImplementedError

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
    def requiredcode(self) -> Optional[Union[str, list[str]]]:
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
        In this case, an error will be raised when patchmethod is called
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def canpatchfields(self) -> bool:
        """
        Whether this patch can be used on fields

        Even if this is True, the patch still may not work on some fields due to factors like data types.
        In this case, an error will be raised when patchfield is called
        """
        raise NotImplementedError

    def patchmethod(self, classname: str, name: str, datatype: str, offset: str) -> str:
        """
        This method does the actual work of generating the patch code
        Patches a method

        The patch code does not have to be a standalone script, but it does have to guarantee
        that it will not cause conflicts or issues with code from other patches

        :param classname: The name of the class the method is in
        :param name: The name of the method to patch
        :param datatype: The data type of the method to patch, including any modifiers, but not access modifiers
        :param offset: The offset of the method to patch
        :return: The generated code that patches the method

        :raises NotImplementedError: The patch does not work on methods
        :raises NotImplementedError: The patch does not work on methods with this data type

        Does not have to be implemented
        """
        raise NotImplementedError(f"{type(self).__name__} patch does not work on methods")

    def patchfield(self, name: str, datatype: str, offset: Optional[str]) -> str:
        """
        This method does the actual work of generating the patch code
        Patches a field

        The patch code does not have to be a standalone script, but it does have to guarantee
        that it will not cause conflicts or issues with code from other patches

        :param classname: The name of the class the field is in
        :param name: The name of the field to patch
        :param datatype: The data type of the field to patch, including any modifiers, but not access modifiers
        :param offset: The offset of the field to patch. None if no offset.
        :return: The generated code that patches the field

        :raises NotImplementedError: The patch does not work on methods
        :raises NotImplementedError: The patch does not work on methods with this data type

        Does not have to be implemented
        """
        raise NotImplementedError(f"{type(self).__name__} patch does not work on fields")


class HexPatch(Patch):
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
        self.newhex = patchdata

    def _frompatch(self, patchtype: PatchType, patch: PatchImplementation) -> None:
        match patchtype:
            case _:
                raise ValueError

    @property
    def requiredcode(self) -> Optional[Union[str, list[str]]]:
        return """--[[ Memory patch functions by geokar2006 - \
https://github.com/geokar2006/Game-Guardian-Easy-MemoryPatch --]]
local function MemoryPatch(a,b,c)local d,e,f,g,h,j='',false,false,{},{},0;local function k(a)return#a>0 and 
a:lower():find("[^%dabcdef]")==nil;end;local function l(a,b)local r=''local function f(v)v=string.format(
"%X",v)if#v==1 then return"0"..v;end;return v;end;for i=0,b-1 do r=r..f(gg.getValues({{address=a+i,flags=gg.TYPE_BYTE}})[1].value)end;return r;end;local function m(a)local r = ''if#a==0 then return false;end;for i=1,#a,2 do r=r..a:sub(i,i+1)end;return r:upper()end;local function n(a,b)local r,i={},0;for v in a:gmatch("%S%S")do table.insert(r,{address=b+i,flags=gg.TYPE_BYTE,value=v.."r"})i=i+1;end;return r;end;local o={Modify=function()if e and not f then gg.setValues(g)f=true;return true;end;return false;end,Restore=function()if e and f then gg.setValues(h)f=false;return true;end;return false;end,GetInfo=function()return{ok=e,lib=a,offset=string.format("0x%X",j).." + "..string.format("0x%X",b),hex=c,originalHex=d}end,IsModified=function()return f;end}c=c:gsub(" ", ""):gsub("0x", ""):upper()if not k(c)then print("[MemoryPatch] Hex is wrong for "..o.GetInfo())return o;end;for _,v in ipairs(gg.getRangesList(a)) do if v.type=="r-xp"or v.state=="Xa"then j=v.start;e=true;break;end;end;if not e then print("[MemoryPatch] Lib not found for "..o.GetInfo())return o;end;d=m(l(j+b,(#c+#c%2)/2))if #c<#d then c=c..d:sub(#d)end;g=n(c,j+b)h=n(d,j+b)return o;end"""  # noqa: E501

    @property
    def canpatchmethods(self) -> bool:
        return True

    @property
    def canpatchfields(self) -> bool:
        return False

    def patchmethod(self, name: str, datatype: str, offset: str) -> str:
        pass


class ArmPatch(Patch):
    ...


class NopPatch(Patch):
    ...


class IntPatch(Patch):
    ...


class BoolPatch(Patch):
    ...


class FloatPatch(Patch):
    """
    Stored as float. When patching, rounds and converts to string using f"{VALUE:.PRECISIONf}"
    """
    ...


class StringPatch(Patch):
    ...


class CharPatch(Patch):
    """
    Stored as string. When patching, converts to integer using ord(VALUE)
    """
    ...
