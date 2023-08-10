using System.Text;

namespace pman;

public sealed class SecureXmlDocument : IDisposable
{
    private const string InvalidParameter = "invalid XML tag parameter";
    private const string UnterminatedParameter = "unterminated XML tag parameter";
    private const string UnterminatedTag = "unterminated tag";
    private const string InvalidXmlTag = "invalid XML tag";
    private const string UnexpectedEndOfData = "unexpected end of data";
    //private const string UnexpectedEndOfTag = "unexpected end of tag";
    private const string InvalidEndTag = "invalid end tag";
    private const string TooShortData = "too short data";
    private const string XmlTagExpected = "XML tag expected"; 

    public class XmlTag : IDisposable
    {
        public readonly string Name;
        public readonly Dictionary<string, string> Properties;
        public readonly byte[] Value;
        public readonly Dictionary<string, XmlTag> Children;

        private readonly byte[] _contents;
        private int _offset;
        private byte[] _nameBytes;
    
        public XmlTag(byte[] contents, int offset)
        {
            _contents = contents;
            _offset = offset;

            // name
            GetName('>', "XML tag without name", "unterminated tag name", out Name);
            _nameBytes = Encoding.UTF8.GetBytes(Name);
            
            // properties
            Properties = new Dictionary<string, string>();
            while (_offset < contents.Length && _contents[_offset] != '>')
                MayBeAddParameter();
            _offset++;
            if (_offset >= contents.Length)
                throw new FormatException(UnterminatedTag);
            
            // value
            var valueOffset = _offset;
            SearchFor('<', UnexpectedEndOfData);
            var l = _offset - valueOffset - 1;
            Value = new byte[l];
            Array.Copy(_contents, valueOffset, Value, 0, l);

            // children
            Children = new Dictionary<string, XmlTag>();
            while (!IsTagEnd())
            {
                var tag = new XmlTag(_contents, _offset);
                Children[tag.Name] = tag;
                _offset = tag._offset;
                SearchFor('<', UnterminatedTag);
            }
        }

        private bool IsTagEnd()
        {
            if (_contents[_offset] == '/')
            {
                if (_offset + _nameBytes.Length + 1 >= _contents.Length)
                    throw new FormatException(UnexpectedEndOfData);
                _offset++;
                if (!_nameBytes.SequenceEqual(new ArraySegment<byte>(_contents, _offset, _nameBytes.Length)))
                    throw new FormatException(InvalidEndTag);
                _offset += _nameBytes.Length;
                if (_contents[_offset] != '>')
                    throw new FormatException(InvalidEndTag);
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
                throw new FormatException(errorMessage);
        }

        private void SkipSpaces(string errorMessage)
        {
            while (_offset < _contents.Length && char.IsWhiteSpace((char)_contents[_offset]))
                _offset++;
            if (_offset == _contents.Length)
                throw new FormatException(errorMessage);
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
                throw new FormatException(emptyNameErrorMessage);
            if (paramsOffset == _contents.Length)
                throw new FormatException(eofErrorMessage);
            name = Encoding.UTF8.GetString(_contents, _offset, paramsOffset - _offset);
            _offset = paramsOffset;
        }

        public void MayBeAddParameter()
        {
            // skipping spaces
            SkipSpaces(InvalidParameter);
            // end of tag
            if (_contents[_offset] == '>')
                return;
            if (_contents[_offset] == '/')
            {
                _offset++;
                if (_offset == _contents.Length || _contents[_offset] != '>')
                    throw new FormatException(InvalidParameter);
                return;
            }

            // getting name
            GetName('=', "XML parameter without name", UnterminatedParameter, out var name);
            // skipping spaces
            SkipSpaces(UnterminatedParameter);
            // validating
            if (_contents[_offset] != '=')
                throw new FormatException(InvalidParameter);
            _offset++;
            // skipping spaces
            SkipSpaces(UnterminatedParameter);
            // validating
            if (_contents[_offset] != '"')
                throw new FormatException(InvalidParameter);
            _offset++;
            var valueOffset = _offset;
            while (valueOffset < _contents.Length && _contents[valueOffset] != '"')
                valueOffset++;
            if (valueOffset == _contents.Length)
                throw new FormatException(UnterminatedParameter);
            var value = Encoding.UTF8.GetString(_contents, _offset, valueOffset - _offset);
            if (Properties.ContainsKey(name))
                throw new FormatException("duplicate parameter name");
            Properties[name] = value;
            _offset = valueOffset + 1;
        }

        public void Dispose()
        {
            Array.Clear(Value);
            foreach (var child in Children.Values)
                child.Dispose();
        }
    }

    public readonly XmlTag Root;

    public SecureXmlDocument(byte[] contents, int offset)
    {
        if (offset + 7 >= contents.Length)
            throw new FormatException(TooShortData);
        if (contents[offset] != '<')
            throw new FormatException(XmlTagExpected);
        offset++;
        if (contents[offset] == '?')
        {
            offset++;
            while (offset < contents.Length && contents[offset] != '<')
                offset++;
            offset++;
            if (offset >= contents.Length)
                throw new FormatException(XmlTagExpected);
        }
        Root = new XmlTag(contents, offset);
    }

    public void Dispose()
    {
        Root.Dispose();
    }
}