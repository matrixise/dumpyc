#!/usr/bin/env python
import sys
import struct
import enum
from lxml import etree
import collections
import time
import opcode   # KISS, but need to implement the right opcodes in fct(version of python)
from datetime import datetime


@enum.unique
class MAGIC_NUMBER(enum.IntEnum):
    MAGIC_2_7   = 0x0A0DF303
    MAGIC_3_0   = 0x0A0D0C3B
    MAGIC_3_1   = 0x0A0D0C4F
    MAGIC_3_2   = 0x0A0D0C6C
    MAGIC_3_3   = 0x0A0D0C9E
    MAGIC_3_4   = 0x0A0D0CEE
    MAGIC_3_5   = 0x0A0D0D16
    MAGIC_3_5_2 = 0x0A0D0D17
    MAGIC_3_6   = 0xA0D00D32

    @property
    def version(self):
        if not hasattr(self, '_version'):
            _, major, minor, *a = self.name.split('_')
            patch_level = a[0] if a else 0
            self._version = int(major), int(minor), int(patch_level)
        return self._version

    def to_dotted_string(self):
        return '.'.join(map(str, self._version))
        
    major_version = property(lambda x: x.version[0])
    minor_version = property(lambda x: x.version[1])
    patch_level = property(lambda x: x.version[2])


class Chunk:
    def __init__(self, offset=0, value=0, bytes=b'', size=0):
        self.offset = offset
        self.value = value
        self.bytes = bytes
        self.size = size

    def to_xml(self, root):
        root.attrib['offset'] = str(self.offset)
        root.attrib['size'] = str(self.size)
        root.attrib['bytes'] = repr(self.bytes)
        root.text = str(self.value)

class Reader:
    def __init__(self, fp):
        self._fp = fp

    def read_byte(self):
        offset = self._fp.seek(0, 1)
        bytes_ = self._fp.read(1)
        value = struct.unpack('c', bytes_)[0]
        return Chunk(offset=offset,
                     value=int.from_bytes(value, sys.byteorder),
                     bytes=bytes_,
                     size=1)
        
    def read_long(self):
        offset = self._fp.seek(0, 1)
        bytes_ = self._fp.read(4)
        value = struct.unpack('=L', bytes_)[0]
        return Chunk(offset=offset, value=value, bytes=bytes_, size=4)
        
    def read_bytes(self, number_of_bytes):
        offset = self._fp.seek(0, 1)
        bytes_ = self._fp.read(number_of_bytes)
        return Chunk(
            offset=offset,
            value=bytes_,
            bytes=bytes_,
            size=number_of_bytes
        )
    
class PycModule:
    def __init__(self, filename):
        self.filename = filename
        self.version = None
        self.header = None
        self.body = None

    def to_dict(self):
        return {
            'filename': self.filename,
            'version': self.version,
            'header': self.header.to_dict(),
            'body': {'type': self.body['type'],
                     'object': self.body['object'].to_dict()}
        }

    def to_xml(self, root=None):
        if root is None:
            root = etree.Element('dump')

        root.attrib['filename'] = self.filename
        root.attrib['version'] = '.'.join(map(str, self.version))
        
        self.header.to_xml(root)
        self.body.to_xml(etree.SubElement(root, 'body'))

        return root

    def set_version(self, magic_number):
        for _, t in MAGIC_NUMBER.__members__.items():
            if t.value == int(magic_number):
                self.version = t.version
                return
        else:
            raise Exception("undefined version of Python")
                

    def parse(self):
        with open(self.filename, 'rb') as fp:
            reader = Reader(fp)
            self.header = PycHeader.parse(reader, self)
            self.body = PyObject.parse(reader, self)

class PycHeader:
    def __init__(self, module):
        self.module = module
        self.magic_number = None
        self.time_stamp = None
        self.size = None

    @classmethod
    def parse(cls, reader, module):
        instance = cls(module)
        instance.magic_number = reader.read_long()

        module.set_version(instance.magic_number.value) #['value'])
        instance.time_stamp = reader.read_long()
        if module.version >= (3, 2):
            instance.size = reader.read_long()

        return instance

    def to_dict(self):
        return {
            'magic_number': self.magic_number,
            'time_stamp': self.time_stamp,
            'size': self.size,
        }

    def to_xml(self, root):
        parent = etree.SubElement(root, 'header')

        node = etree.SubElement(parent, 'magic_number')
        self.magic_number.to_xml(node)
        node.text = '.'.join(map(str, self.module.version))

        node = etree.SubElement(parent, 'time_stamp')
        self.time_stamp.to_xml(node)

        s = time.localtime(self.time_stamp.value)
        dt = datetime.fromtimestamp(time.mktime(s))
        node.text = dt.isoformat()
        # node.text = time.asctime(time.localtime(self.time_stamp.value))

        if self.module.version >= (3, 2):
            node = etree.SubElement(parent, 'size')
            self.size.to_xml(node)
            node.text = str(self.size.value)
            
PyNone = None

class InvalidType(Exception):
    pass

def raise_invalid(reader, module):
    raise InvalidType("Unvalid type")

class PySegment:
    def __init__(self, type=None, object=None):
        self._type = type
        self._object = object

    def to_xml(self, root):
        node = etree.SubElement(root, 'type')
        self._type.to_xml(node)
        
        self._object.to_xml(root)
            
class PyObject:
    def __init__(self, type=None):
        self._type = type

    def to_xml(self, root):
        etree.SubElement(root, 'py-object', type=self._type)
    
    @classmethod
    def parse(cls, reader, module):
        current_byte = reader.read_byte()
        current_type = current_byte.value & 0x7F
        
        MAPPING = {
            99: PyCodeObject.parse,
            115: PyString.parse,
            41: PySmallTuple.parse,
            90: PyShortAsciiInterned.parse,
            78: lambda reader, module: PyNone,
            114: PyReference.parse,
            122: PyShortAscii.parse
        }

        try:
            return MAPPING.get(current_type, raise_invalid)(reader, module)
        except InvalidType:
            print("Invalid Type: %r %r" % (current_type, current_byte))
            
    def to_dict(self):
        d = {
            '_type': self.__class__.__name__,
        }

        for k, v in self.__dict__.items():
            v2 = v
            if isinstance(v, dict) and v.get('object'):
                v2['object'] = v2['object'].to_dict()
            elif isinstance(v, list):
                v2 = []
                for item in v:
                    if isinstance(item, dict):
                        item2 = dict(item)
                        if item.get('object'):
                            item2['object'] = item2['object'].to_dict()
                        v2.append(item2)
                    else:
                        v2.append(item.to_dict())
                    
            d[k] = v2


        return d
            
PyNone = PyObject('TYPE_NONE')
    
class PyString(PyObject):
    @classmethod
    def parse(cls, reader, module):
        instance = PyString()
        instance.size = reader.read_long()
        instance.value = reader.read_bytes(instance.size.value)
        return instance

    def to_xml(self, root):
        node = etree.SubElement(root, 'string')
        node.attrib['size'] = str(self.size.value)
        node.text = str(self.value.bytes)

class PySmallTuple(PyObject):
    @classmethod
    def parse(cls, reader, module):
        instance = cls()
        instance.size = reader.read_byte()
        instance.items = [
            PyObject.parse(reader, module)
            for i in range(instance.size.value)
        ]

        return instance

    def to_xml(self, root):
        node = etree.SubElement(root, 'small-tuple')
        self.size.to_xml(etree.SubElement(node, 'size'))

        items_node = etree.SubElement(node, 'items')
        for item in self.items:
            item.to_xml(etree.SubElement(items_node, 'item'))


class PyShortAscii(PyObject):
    @classmethod
    def parse(cls, reader, module):
        instance = cls()
        instance.size = reader.read_byte()
        instance.value = reader.read_bytes(instance.size.value)
        return instance

    def to_xml(self, root):
        node = etree.SubElement(root, 'short-ascii')
        self.size.to_xml(etree.SubElement(node, 'size'))
        self.value.to_xml(etree.SubElement(node, 'value'))

    
class PyShortAsciiInterned(PyShortAscii):
    @classmethod
    def parse(cls, reader, module):
        instance = cls()
        instance.size = reader.read_byte()
        instance.value = reader.read_bytes(instance.size.value)
        return instance
    
    def to_xml(self, root):
        node = etree.SubElement(root, 'short-ascii-interned')
        self.size.to_xml(etree.SubElement(node, 'size'))
        self.value.to_xml(etree.SubElement(node, 'value'))


class PyReference(PyObject):
    @classmethod
    def parse(cls, reader, module):
        instance = cls()
        instance.index = reader.read_long()
        return instance

    def to_xml(self, root):
        node = etree.SubElement(root, 'reference')
        self.index.to_xml(node)
        
class PyCodeObject(PyObject):
    @classmethod
    def parse(cls, reader, module):
        instance = cls()

        for item in ('arg_count', 'kw_only_arg_count',
                     'num_locals', 'stack_size', 'flags'):
            setattr(instance, item, reader.read_long())

        for item in ('code', 'consts', 'names', 'varnames',
                     'freevars', 'cellvars', 'filename', 'name'):
            setattr(instance, item, PyObject.parse(reader, module))
            
        instance.firstline = reader.read_long()
        instance.table = PyObject.parse(reader, module)

        return instance

    def code_to_xml(self, code, root):
        for item in code:
            node = etree.SubElement(root, 'bytecode')
            node.attrib['byte'] = str(item[1]).zfill(3)
            node.attrib['code'] = item[0]
            if item[2] is not None:
                node.attrib['operand'] = str(item[2])
            if item[3] is not None:
                node.attrib['arguments'] = str(item[3])

    
    def parse_bytecode(self, code):
        container = []

        def consume(cons):
            keyword = next(cons, None)
            
            arguments, operand = None, None
            if keyword is not None:
                if keyword >= opcode.HAVE_ARGUMENT:
                    operand = next(cons, None)
                    arguments = next(cons, None)
            return keyword, operand, arguments

        consumer = iter(code)
        while 1:
            keyword, operand, arguments = consume(consumer)
            if keyword is None:
                break
            container.append((opcode.opname[keyword], keyword, operand, arguments))
            
        return container
        
    def to_xml(self, root):
        parent = etree.SubElement(root, 'code')

        ITEMS = ('arg_count', 'kw_only_arg_count', 'num_locals',
                 'stack_size', 'flags')
        for item in ITEMS:
            field = getattr(self, item)
            node = etree.SubElement(parent, item)
            field.to_xml(node)

        code_node = etree.SubElement(parent, 'code')
        self.code.to_xml(etree.SubElement(code_node, 'original'))

        array_node = etree.SubElement(code_node, 'array')
        array_node.text = str([int(x) for x in self.code.value.bytes])
        
        code = self.parse_bytecode(self.code.value.bytes)
        self.code_to_xml(code, etree.SubElement(code_node, 'bytecodes'))

        ITEMS = ('consts', 'names', 'varnames', 'freevars',
                 'cellvars', 'filename', 'name', 'firstline', 'table')
        
        for item in ITEMS:
            field = getattr(self, item)
            node = etree.SubElement(parent, item)
            field.to_xml(node)

def main(filename):
    pyc = PycModule(filename)
    pyc.parse()
    
    root = pyc.to_xml()
    sys.stdout.write(etree.tostring(root, pretty_print=True).decode('utf-8'))

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
