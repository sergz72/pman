using System.Text;
using pman.utils;

namespace pman;

public sealed class SecureXmlDocument : IDisposable
{
    private const string InvalidParameter = "invalid XML tag parameter";
    private const string UnterminatedParameter = "unterminated XML tag parameter";
    private const string UnterminatedTag = "unterminated tag";
    private const string InvalidXmlTag = "invalid XML tag";
    private const string UnexpectedEndOfData = "unexpected end of data";
    private const string InvalidEndTag = "invalid end tag";
    private const string TooShortData = "too short data";
    private const string XmlTagExpected = "XML tag expected";
    private const string PathNotFound = "path not found";
    private const string MoreThanOneKeyFound = "more than one key found";

    private class SecureXmlDocumentException: Exception
    {
        public SecureXmlDocumentException(string message) : base(message)
        {
        }
    }

    public class XmlTag : IDisposable
    {
        public readonly string Name;
        public readonly Dictionary<string, string> Properties;
        public readonly ProtectedBytes? Value;
        public readonly Dictionary<string, List<XmlTag>> Children;

        private readonly byte[] _contents;
        private int _offset;
        private readonly byte[] _nameBytes;
    
        public XmlTag(byte[] contents, int offset, Action<byte[], Dictionary<string, string>>? valueDecryptor)
        {
            _contents = contents;
            _offset = offset;

            // name
            GetName('>', "XML tag without name", "unterminated tag name", out Name);
            _nameBytes = Encoding.UTF8.GetBytes(Name);

            Properties = new Dictionary<string, string>();
            Children = new Dictionary<string, List<XmlTag>>();
            Value = null;
            
            if (_contents[_offset] == '/')
            {
                _offset++;
                if (_offset == _contents.Length || _contents[_offset] != '>')
                    throw new SecureXmlDocumentException(InvalidParameter);
                _offset++;
                return;
            }
            
            // properties
            while (_offset < contents.Length && _contents[_offset] != '>')
                MayBeAddParameter();
            _offset++;
            if (_offset >= contents.Length)
                throw new SecureXmlDocumentException(UnterminatedTag);
            
            // value
            var valueOffset = _offset;
            SearchFor('<', UnexpectedEndOfData);
            var l = _offset - valueOffset - 1;
            var value = new byte[l];
            Array.Copy(_contents, valueOffset, value, 0, l);
            valueDecryptor?.Invoke(value, Properties);
            Value = ProtectedBytes.Protect(value);
            Array.Clear(value);

            // children
            while (!IsTagEnd())
            {
                var tag = new XmlTag(_contents, _offset, valueDecryptor);
                if (Children.TryGetValue(tag.Name, out var v))
                    v.Add(tag);
                else
                {
                    var list = new List<XmlTag> { tag };
                    Children[tag.Name] = list;
                }
                _offset = tag._offset;
                SearchFor('<', UnterminatedTag);
            }
        }

        private bool IsTagEnd()
        {
            if (_contents[_offset] == '/')
            {
                if (_offset + _nameBytes.Length + 1 >= _contents.Length)
                    throw new SecureXmlDocumentException(UnexpectedEndOfData);
                _offset++;
                if (!_nameBytes.SequenceEqual(new ArraySegment<byte>(_contents, _offset, _nameBytes.Length)))
                    throw new SecureXmlDocumentException(InvalidEndTag);
                _offset += _nameBytes.Length;
                if (_contents[_offset] != '>')
                    throw new SecureXmlDocumentException(InvalidEndTag);
                _offset++;
                return true;
            }

            return false;
        }

        private void SearchFor(char value, string errorMessage)
        {
            while (_offset < _contents.Length && _contents[_offset] != value)
                _offset++;
            _offset++;
            if (_offset >= _contents.Length)
                throw new SecureXmlDocumentException(errorMessage);
        }

        private void SkipSpaces(string errorMessage)
        {
            while (_offset < _contents.Length && char.IsWhiteSpace((char)_contents[_offset]))
                _offset++;
            if (_offset == _contents.Length)
                throw new SecureXmlDocumentException(errorMessage);
        }

        private void GetName(char endTag, string emptyNameErrorMessage, string eofErrorMessage, out string name)
        {
            // skipping spaces
            SkipSpaces(InvalidXmlTag);
            var paramsOffset = _offset;
            // getting name
            while (paramsOffset < _contents.Length && !char.IsWhiteSpace((char)_contents[paramsOffset]))
            {
                if (_contents[paramsOffset] == endTag)
                    break;

                paramsOffset++;
            }

            if (paramsOffset == _offset)
                throw new SecureXmlDocumentException(emptyNameErrorMessage);
            if (paramsOffset == _contents.Length)
                throw new SecureXmlDocumentException(eofErrorMessage);
            name = Encoding.UTF8.GetString(_contents, _offset, paramsOffset - _offset);
            _offset = paramsOffset;
            // skipping spaces
            SkipSpaces(InvalidParameter);
        }

        public void MayBeAddParameter()
        {
            // end of tag
            if (_contents[_offset] == '>')
                return;
            // getting name
            GetName('=', "XML parameter without name", UnterminatedParameter, out var name);
            // skipping spaces
            SkipSpaces(UnterminatedParameter);
            // validating
            if (_contents[_offset] != '=')
                throw new SecureXmlDocumentException(InvalidParameter);
            _offset++;
            // skipping spaces
            SkipSpaces(UnterminatedParameter);
            // validating
            if (_contents[_offset] != '"')
                throw new SecureXmlDocumentException(InvalidParameter);
            _offset++;
            var valueOffset = _offset;
            while (valueOffset < _contents.Length && _contents[valueOffset] != '"')
                valueOffset++;
            if (valueOffset == _contents.Length)
                throw new SecureXmlDocumentException(UnterminatedParameter);
            var value = Encoding.UTF8.GetString(_contents, _offset, valueOffset - _offset);
            if (Properties.ContainsKey(name))
                throw new SecureXmlDocumentException("duplicate parameter name");
            Properties[name] = value;
            _offset = valueOffset + 1;
            // skipping spaces
            SkipSpaces(InvalidParameter);
        }

        public void Dispose()
        {
            Value?.Dispose();
            foreach (var children in Children.Values)
                children.ForEach(child => child.Dispose());
        }

        public List<XmlTag> FindAll(params string[] path)
        {
            switch (path.Length)
            {
                case 0:
                    throw new SecureXmlDocumentException("empty search path");
                default:
                    if (path[0] != Name)
                        throw new SecureXmlDocumentException(PathNotFound);
                    if (path.Length == 1)
                        return new List<XmlTag> { this };
                    if (Children.TryGetValue(path[1], out var tags))
                    {
                        if (path.Length == 2)
                            return tags;
                        if (tags.Count != 1)
                            throw new SecureXmlDocumentException(MoreThanOneKeyFound);
                        return tags[0].FindAll(path[1..]);
                    }
                    return new List<XmlTag>();
            }
        }

        public ProtectedBytes GetChildValue(string childName)
        {
            if (!Children.TryGetValue(childName, out var names))
                throw new SecureXmlDocumentException($"tag {childName} not found");
            if (names.Count != 1)
                throw new SecureXmlDocumentException($"more than one {childName} tag");
            var value = names[0].Value;
            if (value == null)
                throw new SecureXmlDocumentException($"null {childName} value");
            return value;
        }
    }

    public readonly XmlTag Root;

    public SecureXmlDocument(byte[] contents, int offset, Action<byte[], Dictionary<string, string>>? valueDecryptor)
    {
        if (offset + 7 >= contents.Length)
            throw new SecureXmlDocumentException(TooShortData);
        if (contents[offset] != '<')
            throw new SecureXmlDocumentException(XmlTagExpected);
        offset++;
        if (contents[offset] == '?')
        {
            offset++;
            while (offset < contents.Length && contents[offset] != '<')
                offset++;
            offset++;
            if (offset >= contents.Length)
                throw new SecureXmlDocumentException(XmlTagExpected);
        }
        Root = new XmlTag(contents, offset, valueDecryptor);
    }

    public void Dispose()
    {
        Root.Dispose();
    }

    public List<XmlTag> FindAll(params string[] path)
    {
        return Root.FindAll(path);
    }
}