def config():
    """
    Change these values to make it work!
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
    # Patching time!
    """
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
        as static. This is not case sensitive.
        Examples: int, static void, public Dictionary<string, SaltedInt> 
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    """

    """
    Patchmethod: Function to patch one method.

    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the method is in.
    methodname: Name of the method to patch.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    """

    """
    Patchfield: Function to patch one field.

    Arguments:

    If an argument is not provided, the program will attempt to infer it. However, this is not recommended
    as it may be wrong.
    classname: Name of the class the method is in.
    fieldname: Name of the field to patch.
    patchto: The value to patch to.
    patchtype: The type of data the patch is.
    """

    """
    Patchtype:
    The type of data a patch is.
    If the patch is invalid for a field or method, the program will try to convert the patch value
    to another representation that means the same thing. If it fails to do so, it will throw an error and
    skip the method / field.
    . Hex / HexInstruction(s): Arm instructions in hexadecimal representation. If used on a field, it
        will fail.
    . Arm / ArmInstructions: Arm assembly code for 32bit (arm) or 64bit (arm64).
        Separate instructions with newlines or semicolons. If used on a field, it will fail.
    . Nop: Use on void methods to make them do nothing. An example usage is implementing antiban
        by nopping a Ban method. When this type of patch is used, the patchto value does not matter.
        For consistency, I recommend setting both patchtype and patchto to Nop. If used on a field, it
        will fail.
    . Int / Integer: Whole number. If patchto is a decimal number, the value will be rounded to the nearest
        whole number and a warning will be given. Works for int, char, float, double, byte, and boolean data
        types. If the value exceeds the integer limit of the data type of the method or field, it will fail.
        Can be negative, but if the data type of the method or field is unsigned, it will fail.
    . Bool / Boolean: True or False. Can be python built-in True or False. Can also be a string with the value
        of "true" or "false", which is not case-sensitive.
    . Float / Double: Whole number or decimal number. Works for both float and double data types. If the value
        exceeds the float / double limit of the data type of the method or field, it will fail. Also works for
        int, char, float, double, byte, and boolean data types if the  value is a whole number, though it is
        recommended to use int instead of float in this case.
    . String: Text. Also works for char data type if the value is only a single character that is in the
        UTF-16 charset, in which case the value will be converted to its numerical representation. If any of
        the characters in the string are not in the UTF-16 charset, it will fail.
    - Char / Character: Single character that is in the UTF-16 charset. Patchto can be a 16-bit integer,
        unicode sequence (in which case the value will be converted to its numerical representation), or string.
        If patchto is a string and the string is shorter or longer than one character, it will fail. If patchto
        is not in the UTF-16 charset, it will fail.
    """
    patchall(classname="WeaponSounds", namecontains="Ban", patchmethods=True, patchfields=True, datatype="void",
    patchto=1, patchtype=PatchType.NOP)


"""
Everything below here is the real code - you don't need to look at this!
It's all in one file, so the code is very cluttered and messy.
"""

def patchall():
    """
    Patches all methods, fields, or both in an entire class.

    Classname inference: Last classname that was passed in (fails if first call)
    Namecontains inference: Defaults to None
    Patchmethods inference: Last patchmethods that was passed in (defaults to true if first call)
    Patchfields inference: Last patchfields that was passed in (defaults to true if first call)
    Datatype inference: Last datatype that was passed in (fails if first call)
    Patchto inference: Fails
    Patchtype inference: Tries to choose a type that is compatible with the patchto value. Fails
    if the patchto value is also not specified, or if there is no compatible type
    """


def patchmethod():
    """
    Patches a single method.

    Classname inference: Last classname that was passed in (fails if first call)
    Patchmethods inference: Last patchmethods that was passed in (defaults to true if first call)
    Patchfields inference: Last patchfields that was passed in (defaults to true if first call)
    Datatype inference: Last datatype that was passed in (fails if first call)
    Patchto inference: Fails
    Patchtype inference: Tries to choose a type that is compatible with the patchto value. Fails
    if the patchto value is also not specified, or if there is no compatible type
    """


def patchfield():
    """
    Patches a single field.

    Classname inference: Last classname that was passed in (fails if first call)
    Patchmethods inference: Last patchmethods that was passed in (defaults to true if first call)
    Patchfields inference: Last patchfields that was passed in (defaults to true if first call)
    Datatype inference: Last datatype that was passed in (fails if first call)
    Patchto inference: Fails
    Patchtype inference: Tries to choose a type that is compatible with the patchto value. Fails
    if the patchto value is also not specified, or if there is no compatible type
    """


"""
Requiring python 3.10 or later
"""
import sys
# From https://stackoverflow.com/a/34911547/20558255
if sys.version_info < (3, 10):
    raise RuntimeError("Python 3.10 or later is required. You currently have python %s.%s installed."
                       % sys.version_info[:2])


"""
Installing and importing modules
"""
import os
import importlib
import pkg_resources
import packaging.version
import subprocess
import re
import json
from enum import Enum


def install_module(requirement):
    # Get name of requirement (separate from version)
    requirementname = re.split("\s|~|=|>|<", requirement)[0]
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

    def __init__(self, usedefaults=True, **kwargs):
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
                     ):
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

    def printlog(self):
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

    # noinspection PyPep8Naming
    def warning(self, message: str, Type=None):
        if Type:
            self.Log.append(f"[Warning]: {Type}: {message}")
            if self.printwarnings:
                self.printmessage(f"{Type}: {message}", LoggingLevel.Warning, False, self.colorized)
        else:
            self.Log.append(f"[Warning]: {message}")
            if self.printwarnings:
                self.printmessage(message, LoggingLevel.Warning, False, self.colorized)

colorama.just_fix_windows_console()
logging = Logging(usedefaults=True)


class ArmHex():
    def __init__(self, arm64=False):
        self.arm64 = arm64
        self.architecture = "arm64" if arm64 else "arm"
        if self.arm64:
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def armtohex(self, armcode):
        try:
            """
            1. Assemble armcode to bytes with ks.asm, and grab the result (first item of tuple)
            2. Convert the list of encoded instructions to bytes
            3. Convert the bytes to a hex value
            4. Make the hex uppercase
            """
            return bytes(self.ks.asm(armcode)[0]).hex().upper()
        except KsError as e:
            # ToDo: Error handling
            raise

    def hextoarm(self, hexcode, offset=0x0, delimiter = "\n"):
        if delimiter is None:
            delimiter = ""
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
            # ToDo: Error handling
            raise

armhex = ArmHex(True)
print(armhex.hextoarm(armhex.armtohex("mov w0, #1; ret")))

class PatchType(Enum):
    """
    The type of data a patch is.
    If the patch is invalid for a field or method, the program will try to convert the patch value
    to another representation that means the same thing. If it fails to do so, it will throw an error and
    skip the method / field.
    . Hex / HexInstruction(s): Arm instructions in hexadecimal representation. If used on a field, it
        will fail.
    . Arm / ArmInstructions: Arm assembly code for 32bit (arm) or 64bit (arm64).
        Separate instructions with newlines or semicolons. If used on a field, it will fail.
    . Nop: Use on void methods to make them do nothing. An example usage is implementing antiban
        by nopping a Ban method. When this type of patch is used, the patchto value does not matter.
        For consistency, I recommend setting both patchtype and patchto to Nop. If used on a field, it
        will fail.
    . Int / Integer: Whole number. If patchto is a decimal number, the value will be rounded to the nearest
        whole number and a warning will be given. Works for int, char, float, double, byte, and boolean data
        types. If the value exceeds the integer limit of the data type of the method or field, it will fail.
        Can be negative, but if the data type of the method or field is unsigned, it will fail.
    . Bool / Boolean: True or False. Can be python built-in True or False. Can also be a string with the value
        of "true" or "false", which is not case-sensitive.
    . Float / Double: Whole number or decimal number. Works for both float and double data types. If the value
        exceeds the float / double limit of the data type of the method or field, it will fail. Also works for
        int, char, float, double, byte, and boolean data types if the  value is a whole number, though it is
        recommended to use int instead of float in this case.
    . String: Text. Also works for char data type if the value is only a single character that is in the
        UTF-16 charset, in which case the value will be converted to its numerical representation. If any of
        the characters in the string are not in the UTF-16 charset, it will fail.
    - Char / Character: Single character that is in the UTF-16 charset. Patchto can be a 16-bit integer,
        unicode sequence (in which case the value will be converted to its numerical representation), or string.
        If patchto is a string and the string is shorter or longer than one character, it will fail. If patchto
        is not in the UTF-16 charset, it will fail.
    """
    Hex = 1,
    HexInstruction = 1,
    HexInstructions = 1,
    Arm = 2,
    ArmInstructions = 2,
    Nop = 3,
    Int = 4,
    Integer = 4,
    Bool = 5,
    Boolean = 5,
    Float = 6,
    Double = 6
    String = 7,
    Char = 8,
    Character = 8
