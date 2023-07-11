// ------------------------------------------------------------
// Copyright(c) 2018-2022 Jesse Yurkovich
// Licensed under the MIT License <http://opensource.org/licenses/MIT>.
// See the LICENSE file in the repo root for full license information.
// ------------------------------------------------------------
#pragma once

#include <array>
#include <cstring>
#include <fstream>
#include <istream>
#include <ostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>
#include <map>


// rapidjson
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/error/en.h>

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_MSVC_LANG) && (_MSVC_LANG >= 201703L) && (_MSC_VER >= 1911))
    #define FX_GLTF_HAS_CPP_17
    #define FX_GLTF_NODISCARD [[nodiscard]]
    #define FX_GLTF_INLINE_CONSTEXPR inline constexpr
    #include <string_view>
#else
    #define FX_GLTF_NODISCARD
    #define FX_GLTF_INLINE_CONSTEXPR constexpr
#endif

#if defined(__clang__)
    #if __clang_major__ < 7 || (defined(__cplusplus) && __cplusplus < 201703L)
        #define FX_GLTF_EXPERIMENTAL_FILESYSTEM
    #endif
#elif defined(__GNUC__)
    #if __GNUC__ < 8 || (defined(__cplusplus) && __cplusplus < 201703L)
        #define FX_GLTF_EXPERIMENTAL_FILESYSTEM
    #endif
#elif defined(_MSC_VER)
    #if _MSC_VER < 1914 || (!defined(_HAS_CXX17) || (defined(_HAS_CXX17) && _HAS_CXX17 == 0))
        #define FX_GLTF_EXPERIMENTAL_FILESYSTEM
    #endif
#endif

#ifdef FX_GLTF_EXPERIMENTAL_FILESYSTEM
    #include <experimental/filesystem>
    #define FX_GLTF_FILESYSTEM std::experimental::filesystem::v1
#else
    #include <filesystem>
    #define FX_GLTF_FILESYSTEM std::filesystem
#endif

namespace rapidfx
{
namespace base64
{
    namespace detail
    {
        // clang-format off
        FX_GLTF_INLINE_CONSTEXPR std::array<char, 64> EncodeMap =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        FX_GLTF_INLINE_CONSTEXPR std::array<char, 256> DecodeMap =
        {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
            -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        };
        // clang-format on
    } // namespace detail

    inline std::string Encode(std::vector<uint8_t> const & bytes)
    {
        const std::size_t length = bytes.size();
        if (length == 0)
        {
            return {};
        }

        std::string out{};
        out.reserve(((length * 4 / 3) + 3) & (~3u)); // round up to nearest 4

        uint32_t value = 0;
        int32_t bitCount = -6;
        for (const uint8_t c : bytes)
        {
            value = (value << 8u) + c;
            bitCount += 8;
            while (bitCount >= 0)
            {
                const uint32_t shiftOperand = bitCount;
                out.push_back(detail::EncodeMap.at((value >> shiftOperand) & 0x3fu));
                bitCount -= 6;
            }
        }

        if (bitCount > -6)
        {
            const uint32_t shiftOperand = bitCount + 8;
            out.push_back(detail::EncodeMap.at(((value << 8u) >> shiftOperand) & 0x3fu));
        }

        while (out.size() % 4 != 0)
        {
            out.push_back('=');
        }

        return out;
    }

#if defined(FX_GLTF_HAS_CPP_17)
    inline bool TryDecode(std::string_view in, std::vector<uint8_t> & out)
#else
    inline bool TryDecode(std::string const & in, std::vector<uint8_t> & out)
#endif
    {
        out.clear();

        const std::size_t length = in.length();
        if (length == 0)
        {
            return true;
        }

        if (length % 4 != 0)
        {
            return false;
        }

        out.reserve((length / 4) * 3);

        bool invalid = false;
        uint32_t value = 0;
        int32_t bitCount = -8;
        for (std::size_t i = 0; i < length; i++)
        {
            const uint8_t c = static_cast<uint8_t>(in[i]);
            const char map = detail::DecodeMap.at(c);
            if (map == -1)
            {
                if (c != '=') // Non base64 character
                {
                    invalid = true;
                }
                else
                {
                    // Padding characters not where they should be
                    const std::size_t remaining = length - i - 1;
                    if (remaining > 1 || (remaining == 1 ? in[i + 1] != '=' : false))
                    {
                        invalid = true;
                    }
                }

                break;
            }

            value = (value << 6u) + map;
            bitCount += 6;
            if (bitCount >= 0)
            {
                const uint32_t shiftOperand = bitCount;
                out.push_back(static_cast<uint8_t>(value >> shiftOperand));
                bitCount -= 8;
            }
        }

        if (invalid)
        {
            out.clear();
        }

        return !invalid;
    }
} // namespace base64

namespace gltf
{
    class invalid_gltf_document : public std::runtime_error
    {
    public:
        explicit invalid_gltf_document(char const * message)
            : std::runtime_error(message)
        {
        }

        invalid_gltf_document(char const * message, std::string const & extra)
            : std::runtime_error(CreateMessage(message, extra).c_str())
        {
        }

    private:
        static std::string CreateMessage(char const * message, std::string const & extra)
        {
            return std::string(message).append(" : ").append(extra);
        }
    };

    // Deserialization: base types
    inline void from_json(const rapidjson::Value& in_json, bool& io_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_val = in_json.GetBool();
    }
    inline void from_json(const rapidjson::Value& in_json, int& io_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_val = in_json.GetInt();
    }
    inline void from_json(const rapidjson::Value& in_json, unsigned int& io_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_val = in_json.GetUint();
    }
    inline void from_json(const rapidjson::Value& in_json, float& io_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_val = in_json.GetFloat();
    }
    inline void from_json(const rapidjson::Value& in_json, std::string& io_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_val = in_json.GetString();
    }
    // Deserialization: attributes map
    inline void from_json(const rapidjson::Value& in_json, std::unordered_map<std::string, uint32_t>& io_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        for (rapidjson::Value::ConstMemberIterator iter = in_json.MemberBegin(); iter != in_json.MemberEnd();
            ++iter) {
            io_val[iter->name.GetString()] = iter->value.GetUint();
        }
    }
    // Deserialization: vectors
    template<typename InnerType>
    inline void from_json(const rapidjson::Value& in_json, std::vector<InnerType>& io_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept {
        if (in_json.IsArray()) {
            auto array = in_json.GetArray();
            io_val.resize(array.Size());
            for (uint32_t index = 0; index < io_val.size(); ++index) {
                from_json(array[index], io_val[index], in_alloc);
            }
        }
    }
    // Deserialization: arrays
    template<typename InnerType, std::size_t N>
    inline void from_json(const rapidjson::Value& in_json, std::array<InnerType, N>& io_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept {
        if (in_json.IsArray()) {
            auto array = in_json.GetArray();
            for (uint32_t index = 0; index < N; ++index) {
                from_json(array[index], io_val[index], in_alloc);
            }
        }
    }
    
    // Serialization: base types
    inline void to_json(rapidjson::Value& io_json, const bool& in_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_json.SetBool(in_val);
    }
    inline void to_json(rapidjson::Value& io_json, const int& in_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_json.SetInt(in_val);
    }
    inline void to_json(rapidjson::Value& io_json, const unsigned int& in_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_json.SetUint(in_val);
    }
    inline void to_json(rapidjson::Value& io_json, const float& in_val,
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept {
        io_json.SetFloat(in_val);
    }
    inline void to_json(rapidjson::Value& io_json, const std::string& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept {
        io_json.SetString(in_val.c_str(), in_val.size(), in_alloc);
    }
    // Serialization: attributes map
    inline void to_json(rapidjson::Value& io_json, const std::unordered_map<std::string, uint32_t>& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        for (const auto& [key, val] : in_val)
        {
            rapidjson::Value jsonVal;
            jsonVal.SetUint(val);
            io_json.AddMember(rapidjson::Value(key.c_str(), key.size(), in_alloc), jsonVal, in_alloc);
        }
    }
    // Serialization: vectors
    template<typename InnerType>
    inline void to_json(rapidjson::Value& io_json, const std::vector<InnerType>& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept {
        io_json.SetArray();
        for (uint32_t valIndex = 0; valIndex < in_val.size(); ++valIndex)
        {
            const InnerType& val = in_val[valIndex];
            rapidjson::Value jsonVal;
            to_json(jsonVal, val, in_alloc);
            io_json.PushBack(jsonVal, in_alloc);
        }
    }
    // Serialization: arrays
    template<typename InnerType, std::size_t N>
    inline void to_json(rapidjson::Value& io_json, const std::array<InnerType, N>& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept {
        io_json.SetArray();
        for (uint32_t valIndex = 0; valIndex < N; ++valIndex)
        {
            const InnerType& val = in_val[valIndex];
            rapidjson::Value jsonVal;
            to_json(jsonVal, val, in_alloc);
            io_json.PushBack(jsonVal, in_alloc);
        }
    }

    namespace detail
    {
        // read fields
        
        template <typename TTarget>
        inline void ReadRequiredField(  const char* key,
                                        const rapidjson::Value& in_node,
                                        TTarget & target,
                                        rapidjson::MemoryPoolAllocator<>& in_alloc)
        {
            if (!in_node.HasMember(key))
            {
                throw invalid_gltf_document("Required field not found", std::string(key));
            }
            from_json(in_node[key], target, in_alloc);
        }

        template <typename TTarget>
        inline void ReadOptionalField(  const char* key,
                                        const rapidjson::Value& in_node,
                                        TTarget& target,
                                        rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept
        {
            if (in_node.HasMember(key))
            {
                from_json(in_node[key], target, in_alloc);
            }
        }

        inline void ReadExtensions( const rapidjson::Value& in_node,
                                    std::shared_ptr<rapidjson::Value>& extensions,
                                    rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept
        {
            if (in_node.HasMember("extensions"))
            {
                extensions = std::make_shared<rapidjson::Value>();
                extensions->CopyFrom(in_node["extensions"], in_alloc);
            }
        }
        
        inline void ReadExtras( const rapidjson::Value& in_node,
                                std::shared_ptr<rapidjson::Value>& extras,
                                rapidjson::MemoryPoolAllocator<>& in_alloc) noexcept
        {
            if (in_node.HasMember("extras"))
            {
                extras = std::make_shared<rapidjson::Value>();
                extras->CopyFrom(in_node["extras"], in_alloc);
            }
        }
        
        // write fields


        template <typename TValue>
        inline void WriteField( std::string const& in_key,
                                rapidjson::Value& io_parent,
                                TValue const& in_value,
                                rapidjson::MemoryPoolAllocator<>& in_alloc)
        {
            if (! in_value.empty())
            {
                rapidjson::Value val;
                to_json(val, in_value, in_alloc);
                io_parent.AddMember(rapidjson::Value(in_key.c_str(), in_alloc), val, in_alloc);
            }
        }

        template <>
        inline void WriteField(std::string const& in_key,
                                    rapidjson::Value& io_parent,
                                    int const& in_value,
                                    rapidjson::MemoryPoolAllocator<>& in_alloc)
        {
            rapidjson::Value val;
            to_json(val, in_value, in_alloc);
            io_parent.AddMember(rapidjson::Value(in_key.c_str(), in_alloc), val, in_alloc);
        }

        template <>
        inline void WriteField( std::string const& in_key,
                                rapidjson::Value& io_parent,
                                float const& in_value,
                                rapidjson::MemoryPoolAllocator<>& in_alloc)
        {
            rapidjson::Value val;
            to_json(val, in_value, in_alloc);
            io_parent.AddMember(rapidjson::Value(in_key.c_str(), in_alloc), val, in_alloc);
        }

        template <typename TValue>
        inline void WriteField( std::string const& in_key,
                                rapidjson::Value& io_parent,
                                TValue const& in_value,
                                TValue const& in_defaultValue,
                                rapidjson::MemoryPoolAllocator<>& in_alloc)
        {
            if (in_value != in_defaultValue)
            {
                rapidjson::Value val;
                to_json(val, in_value, in_alloc);
                io_parent.AddMember(rapidjson::Value(in_key.c_str(), in_alloc), val, in_alloc);
            }
        }
        
        inline void WriteField( std::string const& in_key,
                                rapidjson::Value& io_parent,
                                const rapidjson::Value& in_value,
                                rapidjson::MemoryPoolAllocator<>& in_alloc)
        {
            if (in_value.IsObject())
            {
                rapidjson::Value val;
                val.CopyFrom(in_value, in_alloc);
                io_parent.AddMember(rapidjson::Value(in_key.c_str(), in_alloc), val, in_alloc);
            }
        }

        inline FX_GLTF_FILESYSTEM::path GetDocumentRootPath(FX_GLTF_FILESYSTEM::path const & documentFilePath)
        {
            return documentFilePath.parent_path();
        }

        inline FX_GLTF_FILESYSTEM::path CreateBufferUriPath(FX_GLTF_FILESYSTEM::path const & documentRootPath, std::string const & bufferUri)
        {
            // Prevent simple forms of path traversal from malicious uri references...
            if (bufferUri.empty() || bufferUri.find("..") != std::string::npos || bufferUri.front() == '/' || bufferUri.front() == '\\')
            {
                throw invalid_gltf_document("Invalid buffer.uri value", bufferUri);
            }

            return documentRootPath / bufferUri;
        }

        struct ChunkHeader
        {
            uint32_t chunkLength{};
            uint32_t chunkType{};
        };

        struct GLBHeader
        {
            uint32_t magic{};
            uint32_t version{};
            uint32_t length{};

            ChunkHeader jsonHeader{};
        };

        FX_GLTF_INLINE_CONSTEXPR uint32_t DefaultMaxBufferCount = 8;
        FX_GLTF_INLINE_CONSTEXPR uint32_t DefaultMaxMemoryAllocation = 32 * 1024 * 1024;
        FX_GLTF_INLINE_CONSTEXPR std::size_t HeaderSize{ sizeof(GLBHeader) };
        FX_GLTF_INLINE_CONSTEXPR std::size_t ChunkHeaderSize{ sizeof(ChunkHeader) };
        FX_GLTF_INLINE_CONSTEXPR uint32_t GLBHeaderMagic = 0x46546c67u;
        FX_GLTF_INLINE_CONSTEXPR uint32_t GLBChunkJSON = 0x4e4f534au;
        FX_GLTF_INLINE_CONSTEXPR uint32_t GLBChunkBIN = 0x004e4942u;

        FX_GLTF_INLINE_CONSTEXPR char const * const MimetypeApplicationOctet = "data:application/octet-stream;base64";
        FX_GLTF_INLINE_CONSTEXPR char const * const MimetypeGLTFBuffer = "data:application/gltf-buffer;base64";
        FX_GLTF_INLINE_CONSTEXPR char const * const MimetypeImagePNG = "data:image/png;base64";
        FX_GLTF_INLINE_CONSTEXPR char const * const MimetypeImageJPG = "data:image/jpeg;base64";
    } // namespace detail

    namespace defaults
    {
        FX_GLTF_INLINE_CONSTEXPR std::array<float, 16> IdentityMatrix{ 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1 };
        FX_GLTF_INLINE_CONSTEXPR std::array<float, 4> IdentityRotation{ 0, 0, 0, 1 };
        FX_GLTF_INLINE_CONSTEXPR std::array<float, 4> IdentityVec4{ 1, 1, 1, 1 };
        FX_GLTF_INLINE_CONSTEXPR std::array<float, 3> IdentityVec3{ 1, 1, 1 };
        FX_GLTF_INLINE_CONSTEXPR std::array<float, 3> NullVec3{ 0, 0, 0 };
        FX_GLTF_INLINE_CONSTEXPR float IdentityScalar = 1;
        FX_GLTF_INLINE_CONSTEXPR float FloatSentinel = 10000;

        FX_GLTF_INLINE_CONSTEXPR bool AccessorNormalized = false;

        FX_GLTF_INLINE_CONSTEXPR float MaterialAlphaCutoff = 0.5f;
        FX_GLTF_INLINE_CONSTEXPR bool MaterialDoubleSided = false;
    } // namespace defaults

    using Attributes = std::unordered_map<std::string, uint32_t>;

    struct NeverEmpty
    {
        FX_GLTF_NODISCARD static bool empty() noexcept
        {
            return false;
        }
    };

    struct Accessor
    {
        enum class ComponentType : uint16_t
        {
            None = 0,
            Byte = 5120,
            UnsignedByte = 5121,
            Short = 5122,
            UnsignedShort = 5123,
            UnsignedInt = 5125,
            Float = 5126
        };

        enum class Type : uint8_t
        {
            None,
            Scalar,
            Vec2,
            Vec3,
            Vec4,
            Mat2,
            Mat3,
            Mat4
        };

        struct Sparse
        {
            struct Indices : NeverEmpty
            {
                uint32_t bufferView{};
                uint32_t byteOffset{};
                ComponentType componentType{ ComponentType::None };

                std::shared_ptr<rapidjson::Value> extensions;
                std::shared_ptr<rapidjson::Value> extras;
            };

            struct Values : NeverEmpty
            {
                uint32_t bufferView{};
                uint32_t byteOffset{};

                std::shared_ptr<rapidjson::Value> extensions;
                std::shared_ptr<rapidjson::Value> extras;
            };

            int32_t count{};
            Indices indices{};
            Values values{};

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;

            FX_GLTF_NODISCARD bool empty() const noexcept
            {
                return count == 0;
            }
        };

        int32_t bufferView{ -1 };
        uint32_t byteOffset{};
        uint32_t count{};
        bool normalized{ defaults::AccessorNormalized };

        ComponentType componentType{ ComponentType::None };
        Type type{ Type::None };
        Sparse sparse;

        std::string name;
        std::vector<float> max{};
        std::vector<float> min{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Animation
    {
        struct Channel
        {
            struct Target : NeverEmpty
            {
                int32_t node{ -1 };
                std::string path{};

                std::shared_ptr<rapidjson::Value> extensions;
                std::shared_ptr<rapidjson::Value> extras;
            };

            int32_t sampler{ -1 };
            Target target{};

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;
        };

        struct Sampler
        {
            enum class Type
            {
                Linear,
                Step,
                CubicSpline
            };

            int32_t input{ -1 };
            int32_t output{ -1 };

            Type interpolation{ Sampler::Type::Linear };

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;
        };

        std::string name{};
        std::vector<Channel> channels{};
        std::vector<Sampler> samplers{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Asset : NeverEmpty
    {
        std::string copyright{};
        std::string generator{};
        std::string minVersion{};
        std::string version{ "2.0" };

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Buffer
    {
        uint32_t byteLength{};

        std::string name;
        std::string uri;

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;

        std::vector<uint8_t> data{};

        FX_GLTF_NODISCARD bool IsEmbeddedResource() const noexcept
        {
            return uri.find(detail::MimetypeApplicationOctet) == 0 || uri.find(detail::MimetypeGLTFBuffer) == 0;
        }

        void SetEmbeddedResource()
        {
            uri = std::string(detail::MimetypeApplicationOctet).append(",").append(base64::Encode(data));
        }
    };

    struct BufferView
    {
        enum class TargetType : uint16_t
        {
            None = 0,
            ArrayBuffer = 34962,
            ElementArrayBuffer = 34963
        };

        std::string name;

        int32_t buffer{ -1 };
        uint32_t byteOffset{};
        uint32_t byteLength{};
        uint32_t byteStride{};

        TargetType target{ TargetType::None };

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Camera
    {
        enum class Type
        {
            None,
            Orthographic,
            Perspective
        };

        struct Orthographic : NeverEmpty
        {
            float xmag{ defaults::FloatSentinel };
            float ymag{ defaults::FloatSentinel };
            float zfar{ -defaults::FloatSentinel };
            float znear{ -defaults::FloatSentinel };

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;
        };

        struct Perspective : NeverEmpty
        {
            float aspectRatio{};
            float yfov{};
            float zfar{};
            float znear{};

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;
        };

        std::string name{};
        Type type{ Type::None };

        Orthographic orthographic;
        Perspective perspective;

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Image
    {
        int32_t bufferView{};

        std::string name;
        std::string uri;
        std::string mimeType;

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;

        FX_GLTF_NODISCARD bool IsEmbeddedResource() const noexcept
        {
            return uri.find(detail::MimetypeImagePNG) == 0 || uri.find(detail::MimetypeImageJPG) == 0;
        }

        void MaterializeData(std::vector<uint8_t> & data) const
        {
            char const * const mimetype = uri.find(detail::MimetypeImagePNG) == 0 ? detail::MimetypeImagePNG : detail::MimetypeImageJPG;
            const std::size_t startPos = std::char_traits<char>::length(mimetype) + 1;

#if defined(FX_GLTF_HAS_CPP_17)
            const std::size_t base64Length = uri.length() - startPos;
            const bool success = base64::TryDecode({ &uri[startPos], base64Length }, data);
#else
            const bool success = base64::TryDecode(uri.substr(startPos), data);
#endif
            if (!success)
            {
                throw invalid_gltf_document("Invalid buffer.uri value", "malformed base64");
            }
        }
    };

    struct Material
    {
        enum class AlphaMode : uint8_t
        {
            Opaque,
            Mask,
            Blend
        };

        struct Texture
        {
            int32_t index{ -1 };
            int32_t texCoord{};

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;

            FX_GLTF_NODISCARD bool empty() const noexcept
            {
                return index == -1;
            }
        };

        struct NormalTexture : Texture
        {
            float scale{ defaults::IdentityScalar };
        };

        struct OcclusionTexture : Texture
        {
            float strength{ defaults::IdentityScalar };
        };

        struct PBRMetallicRoughness
        {
            std::array<float, 4> baseColorFactor = { defaults::IdentityVec4 };
            Texture baseColorTexture;

            float roughnessFactor{ defaults::IdentityScalar };
            float metallicFactor{ defaults::IdentityScalar };
            Texture metallicRoughnessTexture;

            std::shared_ptr<rapidjson::Value> extensions;
            std::shared_ptr<rapidjson::Value> extras;

            FX_GLTF_NODISCARD bool empty() const
            {
                return baseColorTexture.empty() && metallicRoughnessTexture.empty() && metallicFactor == 1.0f && roughnessFactor == 1.0f && baseColorFactor == defaults::IdentityVec4;
            }
        };

        float alphaCutoff{ defaults::MaterialAlphaCutoff };
        AlphaMode alphaMode{ AlphaMode::Opaque };

        bool doubleSided{ defaults::MaterialDoubleSided };

        NormalTexture normalTexture;
        OcclusionTexture occlusionTexture;
        PBRMetallicRoughness pbrMetallicRoughness;

        Texture emissiveTexture;
        std::array<float, 3> emissiveFactor = { defaults::NullVec3 };

        std::string name;
        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Primitive
    {
        enum class Mode : uint8_t
        {
            Points = 0,
            Lines = 1,
            LineLoop = 2,
            LineStrip = 3,
            Triangles = 4,
            TriangleStrip = 5,
            TriangleFan = 6
        };

        int32_t indices{ -1 };
        int32_t material{ -1 };

        Mode mode{ Mode::Triangles };

        Attributes attributes{};
        std::vector<Attributes> targets{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Mesh
    {
        std::string name;

        std::vector<float> weights{};
        std::vector<Primitive> primitives{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Node
    {
        std::string name;

        int32_t camera{ -1 };
        int32_t mesh{ -1 };
        int32_t skin{ -1 };

        std::array<float, 16> matrix{ defaults::IdentityMatrix };
        std::array<float, 4> rotation{ defaults::IdentityRotation };
        std::array<float, 3> scale{ defaults::IdentityVec3 };
        std::array<float, 3> translation{ defaults::NullVec3 };

        std::vector<int32_t> children{};
        std::vector<float> weights{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Sampler
    {
        enum class MagFilter : uint16_t
        {
            None,
            Nearest = 9728,
            Linear = 9729
        };

        enum class MinFilter : uint16_t
        {
            None,
            Nearest = 9728,
            Linear = 9729,
            NearestMipMapNearest = 9984,
            LinearMipMapNearest = 9985,
            NearestMipMapLinear = 9986,
            LinearMipMapLinear = 9987
        };

        enum class WrappingMode : uint16_t
        {
            ClampToEdge = 33071,
            MirroredRepeat = 33648,
            Repeat = 10497
        };

        std::string name;

        MagFilter magFilter{ MagFilter::None };
        MinFilter minFilter{ MinFilter::None };

        WrappingMode wrapS{ WrappingMode::Repeat };
        WrappingMode wrapT{ WrappingMode::Repeat };

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;

        FX_GLTF_NODISCARD bool empty() const noexcept
        {
            return name.empty() && magFilter == MagFilter::None && minFilter == MinFilter::None && wrapS == WrappingMode::Repeat && wrapT == WrappingMode::Repeat && !extensions && !extras;
        }
    };

    struct Scene
    {
        std::string name;

        std::vector<uint32_t> nodes{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Skin
    {
        int32_t inverseBindMatrices{ -1 };
        int32_t skeleton{ -1 };

        std::string name;
        std::vector<uint32_t> joints{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Texture
    {
        std::string name;

        int32_t sampler{ -1 };
        int32_t source{ -1 };

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;
    };

    struct Document
    {
        Asset asset;

        std::vector<Accessor> accessors{};
        std::vector<Animation> animations{};
        std::vector<Buffer> buffers{};
        std::vector<BufferView> bufferViews{};
        std::vector<Camera> cameras{};
        std::vector<Image> images{};
        std::vector<Material> materials{};
        std::vector<Mesh> meshes{};
        std::vector<Node> nodes{};
        std::vector<Sampler> samplers{};
        std::vector<Scene> scenes{};
        std::vector<Skin> skins{};
        std::vector<Texture> textures{};

        int32_t scene{ -1 };
        std::vector<std::string> extensionsUsed{};
        std::vector<std::string> extensionsRequired{};

        std::shared_ptr<rapidjson::Value> extensions;
        std::shared_ptr<rapidjson::Value> extras;

        std::shared_ptr<rapidjson::Document> jsonDocument;
    };

    struct ReadQuotas
    {
        uint32_t MaxBufferCount{ detail::DefaultMaxBufferCount };
        uint32_t MaxFileSize{ detail::DefaultMaxMemoryAllocation };
        uint32_t MaxBufferByteLength{ detail::DefaultMaxMemoryAllocation };
    };
    
    // Deserialization: enums
#define FROM_JSON_ENUM(EnumName)                                             \
    inline void from_json(const rapidjson::Value& in_json, EnumName& io_val, \
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept { \
        io_val = (EnumName) (in_json.GetUint());                             \
    }
    FROM_JSON_ENUM(Accessor::ComponentType)
    FROM_JSON_ENUM(BufferView::TargetType)
    FROM_JSON_ENUM(Primitive::Mode)
    FROM_JSON_ENUM(Sampler::MagFilter)
    FROM_JSON_ENUM(Sampler::MinFilter)
    FROM_JSON_ENUM(Sampler::WrappingMode)

    inline void from_json(const rapidjson::Value& in_json, Accessor::Type& io_val, rapidjson::MemoryPoolAllocator<>& /**/)
    {
        std::string type = in_json.GetString();
        if (type == "SCALAR")
        {
            io_val = Accessor::Type::Scalar;
        }
        else if (type == "VEC2")
        {
            io_val = Accessor::Type::Vec2;
        }
        else if (type == "VEC3")
        {
            io_val = Accessor::Type::Vec3;
        }
        else if (type == "VEC4")
        {
            io_val = Accessor::Type::Vec4;
        }
        else if (type == "MAT2")
        {
            io_val = Accessor::Type::Mat2;
        }
        else if (type == "MAT3")
        {
            io_val = Accessor::Type::Mat3;
        }
        else if (type == "MAT4")
        {
            io_val = Accessor::Type::Mat4;
        }
        else
        {
            throw invalid_gltf_document("Unknown accessor.type value", type);
        }
    }

    inline void from_json(const rapidjson::Value& in_json, Accessor::Sparse::Values& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("bufferView", in_json, io_val.bufferView, in_alloc);
    
        detail::ReadOptionalField("byteOffset", in_json, io_val.byteOffset, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Accessor::Sparse::Indices& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("bufferView", in_json, io_val.bufferView, in_alloc);
        detail::ReadRequiredField("componentType", in_json, io_val.componentType, in_alloc);
    
        detail::ReadOptionalField("byteOffset", in_json, io_val.byteOffset, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Accessor::Sparse& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("count", in_json, io_val.count, in_alloc);
        detail::ReadRequiredField("indices", in_json, io_val.indices, in_alloc);
        detail::ReadRequiredField("values", in_json, io_val.values, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Accessor& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("componentType", in_json, io_val.componentType, in_alloc);
        detail::ReadRequiredField("count", in_json, io_val.count, in_alloc);
        detail::ReadRequiredField("type", in_json, io_val.type, in_alloc);
    
        detail::ReadOptionalField("bufferView", in_json, io_val.bufferView, in_alloc);
        detail::ReadOptionalField("byteOffset", in_json, io_val.byteOffset, in_alloc);
        detail::ReadOptionalField("max", in_json, io_val.max, in_alloc);
        detail::ReadOptionalField("min", in_json, io_val.min, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("normalized", in_json, io_val.normalized, in_alloc);
        detail::ReadOptionalField("sparse", in_json, io_val.sparse, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Animation::Channel::Target& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("path", in_json, io_val.path, in_alloc);
    
        detail::ReadOptionalField("node", in_json, io_val.node, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Animation::Channel& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("sampler", in_json, io_val.sampler, in_alloc);
        detail::ReadRequiredField("target", in_json, io_val.target, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Animation::Sampler::Type& io_val, rapidjson::MemoryPoolAllocator<>& /**/)
    {
        std::string type = in_json.GetString();
        if (type == "LINEAR")
        {
            io_val = Animation::Sampler::Type::Linear;
        }
        else if (type == "STEP")
        {
            io_val = Animation::Sampler::Type::Step;
        }
        else if (type == "CUBICSPLINE")
        {
            io_val = Animation::Sampler::Type::CubicSpline;
        }
        else
        {
            throw invalid_gltf_document("Unknown animation.sampler.interpolation value", type);
        }
    }
    
    inline void from_json(const rapidjson::Value& in_json, Animation::Sampler& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("input", in_json, io_val.input, in_alloc);
        detail::ReadRequiredField("output", in_json, io_val.output, in_alloc);
    
        detail::ReadOptionalField("interpolation", in_json, io_val.interpolation, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Animation& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("channels", in_json, io_val.channels, in_alloc);
        detail::ReadRequiredField("samplers", in_json, io_val.samplers, in_alloc);
    
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Asset& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("version", in_json, io_val.version, in_alloc);
        detail::ReadOptionalField("copyright", in_json, io_val.copyright, in_alloc);
        detail::ReadOptionalField("generator", in_json, io_val.generator, in_alloc);
        detail::ReadOptionalField("minVersion", in_json, io_val.minVersion, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Buffer& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("byteLength", in_json, io_val.byteLength, in_alloc);
    
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("uri", in_json, io_val.uri, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, BufferView& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("buffer", in_json, io_val.buffer, in_alloc);
        detail::ReadRequiredField("byteLength", in_json, io_val.byteLength, in_alloc);
    
        detail::ReadOptionalField("byteOffset", in_json, io_val.byteOffset, in_alloc);
        detail::ReadOptionalField("byteStride", in_json, io_val.byteStride, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("target", in_json, io_val.target, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Camera::Type& io_val, rapidjson::MemoryPoolAllocator<>& /**/)
    {
        std::string type = in_json.GetString();
        if (type == "orthographic")
        {
            io_val = Camera::Type::Orthographic;
        }
        else if (type == "perspective")
        {
            io_val = Camera::Type::Perspective;
        }
        else
        {
            throw invalid_gltf_document("Unknown camera.type value", type);
        }
    }
    
    inline void from_json(const rapidjson::Value& in_json, Camera::Orthographic& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("xmag", in_json, io_val.xmag, in_alloc);
        detail::ReadRequiredField("ymag", in_json, io_val.ymag, in_alloc);
        detail::ReadRequiredField("zfar", in_json, io_val.zfar, in_alloc);
        detail::ReadRequiredField("znear", in_json, io_val.znear, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Camera::Perspective& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("yfov", in_json, io_val.yfov, in_alloc);
        detail::ReadRequiredField("znear", in_json, io_val.znear, in_alloc);
    
        detail::ReadOptionalField("aspectRatio", in_json, io_val.aspectRatio, in_alloc);
        detail::ReadOptionalField("zfar", in_json, io_val.zfar, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Camera& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("type", in_json, io_val.type, in_alloc);
    
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    
        if (io_val.type == Camera::Type::Perspective)
        {
            detail::ReadRequiredField("perspective", in_json, io_val.perspective, in_alloc);
        } else if (io_val.type == Camera::Type::Orthographic)
        {
            detail::ReadRequiredField("orthographic", in_json, io_val.orthographic, in_alloc);
        }
    }
    
    inline void from_json(const rapidjson::Value& in_json, Image& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("bufferView", in_json, io_val.bufferView, in_alloc);
        detail::ReadOptionalField("mimeType", in_json, io_val.mimeType, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("uri", in_json, io_val.uri, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Material::AlphaMode& io_val, rapidjson::MemoryPoolAllocator<>& /**/)
    {
        std::string alphaMode = in_json.GetString();
        if (alphaMode == "OPAQUE")
        {
            io_val = Material::AlphaMode::Opaque;
        }
        else if (alphaMode == "MASK")
        {
            io_val = Material::AlphaMode::Mask;
        }
        else if (alphaMode == "BLEND")
        {
            io_val = Material::AlphaMode::Blend;
        }
        else
        {
            throw invalid_gltf_document("Unknown material.alphaMode value", alphaMode);
        }
    }
    
    inline void from_json(const rapidjson::Value& in_json, Material::Texture& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("index", in_json, io_val.index, in_alloc);
        detail::ReadOptionalField("texCoord", in_json, io_val.texCoord, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Material::NormalTexture& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        from_json(in_json, static_cast<Material::Texture&>(io_val), in_alloc);
        detail::ReadOptionalField("scale", in_json, io_val.scale, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Material::OcclusionTexture& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        from_json(in_json, static_cast<Material::Texture&>(io_val), in_alloc);
        detail::ReadOptionalField("strength", in_json, io_val.strength, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Material::PBRMetallicRoughness& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("baseColorFactor", in_json, io_val.baseColorFactor, in_alloc);
        detail::ReadOptionalField("baseColorTexture", in_json, io_val.baseColorTexture, in_alloc);
        detail::ReadOptionalField("metallicFactor", in_json, io_val.metallicFactor, in_alloc);
        detail::ReadOptionalField("metallicRoughnessTexture", in_json, io_val.metallicRoughnessTexture, in_alloc);
        detail::ReadOptionalField("roughnessFactor", in_json, io_val.roughnessFactor, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Material& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("alphaMode", in_json, io_val.alphaMode, in_alloc);
        detail::ReadOptionalField("alphaCutoff", in_json, io_val.alphaCutoff, in_alloc);
        detail::ReadOptionalField("doubleSided", in_json, io_val.doubleSided, in_alloc);
        detail::ReadOptionalField("emissiveFactor", in_json, io_val.emissiveFactor, in_alloc);
        detail::ReadOptionalField("emissiveTexture", in_json, io_val.emissiveTexture, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("normalTexture", in_json, io_val.normalTexture, in_alloc);
        detail::ReadOptionalField("occlusionTexture", in_json, io_val.occlusionTexture, in_alloc);
        detail::ReadOptionalField("pbrMetallicRoughness", in_json, io_val.pbrMetallicRoughness, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Mesh& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("primitives", in_json, io_val.primitives, in_alloc);
    
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("weights", in_json, io_val.weights, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Node& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("camera", in_json, io_val.camera, in_alloc);
        detail::ReadOptionalField("children", in_json, io_val.children, in_alloc);
        detail::ReadOptionalField("matrix", in_json, io_val.matrix, in_alloc);
        detail::ReadOptionalField("mesh", in_json, io_val.mesh, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("rotation", in_json, io_val.rotation, in_alloc);
        detail::ReadOptionalField("scale", in_json, io_val.scale, in_alloc);
        detail::ReadOptionalField("skin", in_json, io_val.skin, in_alloc);
        detail::ReadOptionalField("translation", in_json, io_val.translation, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Primitive & io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("attributes", in_json, io_val.attributes, in_alloc);
    
        detail::ReadOptionalField("indices", in_json, io_val.indices, in_alloc);
        detail::ReadOptionalField("material", in_json, io_val.material, in_alloc);
        detail::ReadOptionalField("mode", in_json, io_val.mode, in_alloc);
        detail::ReadOptionalField("targets", in_json, io_val.targets, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Sampler& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("magFilter", in_json, io_val.magFilter, in_alloc);
        detail::ReadOptionalField("minFilter", in_json, io_val.minFilter, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("wrapS", in_json, io_val.wrapS, in_alloc);
        detail::ReadOptionalField("wrapT", in_json, io_val.wrapT, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Scene& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("nodes", in_json, io_val.nodes, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Skin& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadRequiredField("joints", in_json, io_val.joints, in_alloc);
    
        detail::ReadOptionalField("inverseBindMatrices", in_json, io_val.inverseBindMatrices, in_alloc);
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("skeleton", in_json, io_val.skeleton, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }
    
    inline void from_json(const rapidjson::Value& in_json, Texture& io_val, rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        detail::ReadOptionalField("name", in_json, io_val.name, in_alloc);
        detail::ReadOptionalField("sampler", in_json, io_val.sampler, in_alloc);
        detail::ReadOptionalField("source", in_json, io_val.source, in_alloc);
    
        detail::ReadExtensions(in_json, io_val.extensions, in_alloc);
        detail::ReadExtras(in_json, io_val.extras, in_alloc);
    }

    inline void from_json(const rapidjson::Document& in_doc, Document& document) {
        document.jsonDocument = std::make_shared<rapidjson::Document>();
        rapidjson::MemoryPoolAllocator<>& alloc = document.jsonDocument->GetAllocator();
        detail::ReadRequiredField("asset", in_doc, document.asset, alloc);
        detail::ReadOptionalField("accessors", in_doc, document.accessors, alloc);
        detail::ReadOptionalField("animations", in_doc, document.animations, alloc);
        detail::ReadOptionalField("buffers", in_doc, document.buffers, alloc);
        detail::ReadOptionalField("bufferViews", in_doc, document.bufferViews, alloc);
        detail::ReadOptionalField("cameras", in_doc, document.cameras, alloc);
        detail::ReadOptionalField("materials", in_doc, document.materials, alloc);
        detail::ReadOptionalField("meshes", in_doc, document.meshes, alloc);
        detail::ReadOptionalField("nodes", in_doc, document.nodes, alloc);
        detail::ReadOptionalField("images", in_doc, document.images, alloc);
        detail::ReadOptionalField("samplers", in_doc, document.samplers, alloc);
        detail::ReadOptionalField("scene", in_doc, document.scene, alloc);
        detail::ReadOptionalField("scenes", in_doc, document.scenes, alloc);
        detail::ReadOptionalField("skins", in_doc, document.skins, alloc);
        detail::ReadOptionalField("textures", in_doc, document.textures, alloc);

        detail::ReadOptionalField("extensionsUsed", in_doc, document.extensionsUsed, alloc);
        detail::ReadOptionalField("extensionsRequired", in_doc, document.extensionsRequired, alloc);
        detail::ReadExtensions(in_doc, document.extensions, alloc);
        detail::ReadExtras(in_doc, document.extras, alloc);
    }
    
    // Serialization: enums
#define TO_JSON_ENUM(EnumName)                                             \
    inline void to_json(rapidjson::Value& io_json, const EnumName& in_val, \
                        rapidjson::MemoryPoolAllocator<>& /**/) noexcept { \
        io_json.SetUint((unsigned int) in_val);                            \
    }
    TO_JSON_ENUM(Accessor::ComponentType)
    TO_JSON_ENUM(BufferView::TargetType)
    TO_JSON_ENUM(Primitive::Mode)
    TO_JSON_ENUM(Sampler::MagFilter)
    TO_JSON_ENUM(Sampler::MinFilter)
    TO_JSON_ENUM(Sampler::WrappingMode)
    inline void to_json(rapidjson::Value& io_json, const Accessor::Type in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        switch (in_val)
        {
        case Accessor::Type::Scalar:
            io_json.SetString("SCALAR");
            break;
        case Accessor::Type::Vec2:
            io_json.SetString("VEC2");
            break;
        case Accessor::Type::Vec3:
            io_json.SetString("VEC3");
            break;
        case Accessor::Type::Vec4:
            io_json.SetString("VEC4");
            break;
        case Accessor::Type::Mat2:
            io_json.SetString("MAT2");
            break;
        case Accessor::Type::Mat3:
            io_json.SetString("MAT3");
            break;
        case Accessor::Type::Mat4:
            io_json.SetString("MAT4");
            break;
        default:
            throw invalid_gltf_document("Unknown accessor.type value");
        }
    }

    inline void to_json(rapidjson::Value& io_json, const Accessor::Sparse::Values& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc)
    {
        io_json.SetObject();
        detail::WriteField("bufferView", io_json, in_val.bufferView, static_cast<uint32_t>(-1), in_alloc);
        detail::WriteField("byteOffset", io_json, in_val.byteOffset, {}, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Accessor::Sparse::Indices& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("componentType", io_json, in_val.componentType, Accessor::ComponentType::None,
                           in_alloc);
        detail::WriteField("bufferView", io_json, in_val.bufferView, static_cast<uint32_t>(-1), in_alloc);
        detail::WriteField("byteOffset", io_json, in_val.byteOffset, {}, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Accessor::Sparse& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("count", io_json, in_val.count, -1, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("indices", io_json, in_val.indices, in_alloc);
        detail::WriteField("values", io_json, in_val.values, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Accessor& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("bufferView", io_json, in_val.bufferView, -1, in_alloc);
        detail::WriteField("byteOffset", io_json, in_val.byteOffset, {}, in_alloc);
        detail::WriteField("componentType", io_json, in_val.componentType, Accessor::ComponentType::None,
                           in_alloc);
        detail::WriteField("count", io_json, in_val.count, {}, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("max", io_json, in_val.max, in_alloc);
        detail::WriteField("min", io_json, in_val.min, in_alloc);
        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("normalized", io_json, in_val.normalized, false, in_alloc);
        detail::WriteField("sparse", io_json, in_val.sparse, in_alloc);
        detail::WriteField("type", io_json, in_val.type, Accessor::Type::None, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Animation::Channel::Target& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("node", io_json, in_val.node, -1, in_alloc);
        detail::WriteField("path", io_json, in_val.path, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Animation::Channel& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("sampler", io_json, in_val.sampler, -1, in_alloc);
        detail::WriteField("target", io_json, in_val.target, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Animation::Sampler::Type& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        switch (in_val) {
            case Animation::Sampler::Type::Linear:
                io_json.SetString("LINEAR");
                break;
            case Animation::Sampler::Type::Step:
                io_json.SetString("STEP");
                break;
            case Animation::Sampler::Type::CubicSpline:
                io_json.SetString("CUBICSPLINE");
                break;
        }
    }

    inline void to_json(rapidjson::Value& io_json, const Animation::Sampler& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("input", io_json, in_val.input, -1, in_alloc);
        detail::WriteField("interpolation", io_json, in_val.interpolation, Animation::Sampler::Type::Linear,
                           in_alloc);
        detail::WriteField("output", io_json, in_val.output, -1, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Animation& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("channels", io_json, in_val.channels, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("samplers", io_json, in_val.samplers, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Asset& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("copyright", io_json, in_val.copyright, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("generator", io_json, in_val.generator, in_alloc);
        detail::WriteField("minVersion", io_json, in_val.minVersion, in_alloc);
        detail::WriteField("version", io_json, in_val.version, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Buffer& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("byteLength", io_json, in_val.byteLength, {}, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("uri", io_json, in_val.uri, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const BufferView& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("buffer", io_json, in_val.buffer, -1, in_alloc);
        detail::WriteField("byteLength", io_json, in_val.byteLength, {}, in_alloc);
        detail::WriteField("byteOffset", io_json, in_val.byteOffset, {}, in_alloc);
        detail::WriteField("byteStride", io_json, in_val.byteStride, {}, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("target", io_json, in_val.target, BufferView::TargetType::None, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Camera::Type& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        switch (in_val) {
            case Camera::Type::Orthographic:
                io_json.SetString("orthographic");
                break;
            case Camera::Type::Perspective:
                io_json.SetString("perspective");
                break;
            default:
                throw invalid_gltf_document("Unknown camera.type value");
        }
    }

    inline void to_json(rapidjson::Value& io_json, const Camera::Orthographic& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("xmag", io_json, in_val.xmag, defaults::FloatSentinel, in_alloc);
        detail::WriteField("ymag", io_json, in_val.ymag, defaults::FloatSentinel, in_alloc);
        detail::WriteField("zfar", io_json, in_val.zfar, -defaults::FloatSentinel, in_alloc);
        detail::WriteField("znear", io_json, in_val.znear, -defaults::FloatSentinel, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Camera::Perspective& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("aspectRatio", io_json, in_val.aspectRatio, {}, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("yfov", io_json, in_val.yfov, {}, in_alloc);
        detail::WriteField("zfar", io_json, in_val.zfar, {}, in_alloc);
        detail::WriteField("znear", io_json, in_val.znear, {}, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Camera& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("type", io_json, in_val.type, Camera::Type::None, in_alloc);

        if (in_val.type == Camera::Type::Perspective) {
            detail::WriteField("perspective", io_json, in_val.perspective, in_alloc);
        } else if (in_val.type == Camera::Type::Orthographic) {
            detail::WriteField("orthographic", io_json, in_val.orthographic, in_alloc);
        }
    }

    inline void to_json(rapidjson::Value& io_json, const Image& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("bufferView", io_json, in_val.bufferView,
                           in_val.uri.empty() ? -1
                                             : 0, in_alloc); // bufferView or uri need to be written; even if default 0

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("mimeType", io_json, in_val.mimeType, in_alloc);
        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("uri", io_json, in_val.uri, in_alloc);
    }


    inline void to_json(rapidjson::Value& io_json, const Material::AlphaMode& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        switch (in_val) {
            case Material::AlphaMode::Opaque:
                io_json.SetString("OPAQUE");
                break;
            case Material::AlphaMode::Mask:
                io_json.SetString("MASK");
                break;
            case Material::AlphaMode::Blend:
                io_json.SetString("BLEND");
                break;
        }
    }

    inline void to_json(rapidjson::Value& io_json, const Material::Texture& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        if (! io_json.IsObject())
            io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("index", io_json, in_val.index, -1, in_alloc);
        detail::WriteField("texCoord", io_json, in_val.texCoord, 0, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Material::NormalTexture& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        to_json(io_json, static_cast<Material::Texture const&>(in_val), in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("scale", io_json, in_val.scale, defaults::IdentityScalar, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Material::OcclusionTexture& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        to_json(io_json, static_cast<Material::Texture const&>(in_val), in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("strength", io_json, in_val.strength, defaults::IdentityScalar, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Material::PBRMetallicRoughness& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("baseColorFactor", io_json, in_val.baseColorFactor, defaults::IdentityVec4,
                           in_alloc);
        detail::WriteField("baseColorTexture", io_json, in_val.baseColorTexture, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("metallicFactor", io_json, in_val.metallicFactor, defaults::IdentityScalar,
                           in_alloc);
        detail::WriteField("metallicRoughnessTexture", io_json, in_val.metallicRoughnessTexture, in_alloc);
        detail::WriteField("roughnessFactor", io_json, in_val.roughnessFactor, defaults::IdentityScalar,
                           in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Material& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("alphaCutoff", io_json, in_val.alphaCutoff, defaults::MaterialAlphaCutoff, in_alloc);
        detail::WriteField("alphaMode", io_json, in_val.alphaMode, Material::AlphaMode::Opaque, in_alloc);
        detail::WriteField("doubleSided", io_json, in_val.doubleSided, defaults::MaterialDoubleSided,
                           in_alloc);
        detail::WriteField("emissiveTexture", io_json, in_val.emissiveTexture, in_alloc);
        detail::WriteField("emissiveFactor", io_json, in_val.emissiveFactor, defaults::NullVec3, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("normalTexture", io_json, in_val.normalTexture, in_alloc);
        detail::WriteField("occlusionTexture", io_json, in_val.occlusionTexture, in_alloc);
        detail::WriteField("pbrMetallicRoughness", io_json, in_val.pbrMetallicRoughness, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Mesh& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("primitives", io_json, in_val.primitives, in_alloc);
        detail::WriteField("weights", io_json, in_val.weights, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Node& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("camera", io_json, in_val.camera, -1, in_alloc);
        detail::WriteField("children", io_json, in_val.children, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("matrix", io_json, in_val.matrix, defaults::IdentityMatrix, in_alloc);
        detail::WriteField("mesh", io_json, in_val.mesh, -1, in_alloc);
        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("rotation", io_json, in_val.rotation, defaults::IdentityRotation, in_alloc);
        detail::WriteField("scale", io_json, in_val.scale, defaults::IdentityVec3, in_alloc);
        detail::WriteField("skin", io_json, in_val.skin, -1, in_alloc);
        detail::WriteField("translation", io_json, in_val.translation, defaults::NullVec3, in_alloc);
        detail::WriteField("weights", io_json, in_val.weights, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Primitive& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        detail::WriteField("attributes", io_json, in_val.attributes, in_alloc);

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("indices", io_json, in_val.indices, -1, in_alloc);
        detail::WriteField("material", io_json, in_val.material, -1, in_alloc);
        detail::WriteField("mode", io_json, in_val.mode, Primitive::Mode::Triangles, in_alloc);
        detail::WriteField("targets", io_json, in_val.targets, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Sampler& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();
        if (! in_val.empty()) {
            if (in_val.extensions)
                detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
            if (in_val.extras)
                detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

            detail::WriteField("name", io_json, in_val.name, in_alloc);
            detail::WriteField("magFilter", io_json, in_val.magFilter, Sampler::MagFilter::None, in_alloc);
            detail::WriteField("minFilter", io_json, in_val.minFilter, Sampler::MinFilter::None, in_alloc);
            detail::WriteField("wrapS", io_json, in_val.wrapS, Sampler::WrappingMode::Repeat, in_alloc);
            detail::WriteField("wrapT", io_json, in_val.wrapT, Sampler::WrappingMode::Repeat, in_alloc);
        } else {
            // If a sampler is completely empty we still need to write out an empty object for the
            // encompassing array...
        }
    }

    inline void to_json(rapidjson::Value& io_json, const Scene& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("nodes", io_json, in_val.nodes, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Skin& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("inverseBindMatrices", io_json, in_val.inverseBindMatrices, -1, in_alloc);
        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("skeleton", io_json, in_val.skeleton, -1, in_alloc);
        detail::WriteField("joints", io_json, in_val.joints, in_alloc);
    }

    inline void to_json(rapidjson::Value& io_json, const Texture& in_val,
                        rapidjson::MemoryPoolAllocator<>& in_alloc) {
        io_json.SetObject();

        if (in_val.extensions)
            detail::WriteField("extensions", io_json, *in_val.extensions, in_alloc);
        if (in_val.extras)
            detail::WriteField("extras", io_json, *in_val.extras, in_alloc);

        detail::WriteField("name", io_json, in_val.name, in_alloc);
        detail::WriteField("sampler", io_json, in_val.sampler, -1, in_alloc);
        detail::WriteField("source", io_json, in_val.source, -1, in_alloc);
    }

    inline void to_json(rapidjson::Document& io_json, const Document& in_document) {
        io_json.SetObject();
        rapidjson::MemoryPoolAllocator<>& alloc = io_json.GetAllocator();

        detail::WriteField("accessors", io_json, in_document.accessors, alloc);
        detail::WriteField("animations", io_json, in_document.animations, alloc);
        detail::WriteField("asset", io_json, in_document.asset, alloc);
        detail::WriteField("bufferViews", io_json, in_document.bufferViews, alloc);
        detail::WriteField("buffers", io_json, in_document.buffers, alloc);
        detail::WriteField("cameras", io_json, in_document.cameras, alloc);

        if (in_document.extensions)
            detail::WriteField("extensions", io_json, *in_document.extensions, alloc);
        detail::WriteField("extensionsUsed", io_json, in_document.extensionsUsed, alloc);
        detail::WriteField("extensionsRequired", io_json, in_document.extensionsRequired, alloc);
        if (in_document.extras)
            detail::WriteField("extras", io_json, *in_document.extras, alloc);

        detail::WriteField("images", io_json, in_document.images, alloc);
        detail::WriteField("materials", io_json, in_document.materials, alloc);
        detail::WriteField("meshes", io_json, in_document.meshes, alloc);
        detail::WriteField("nodes", io_json, in_document.nodes, alloc);
        detail::WriteField("samplers", io_json, in_document.samplers, alloc);
        detail::WriteField("scene", io_json, in_document.scene, -1, alloc);
        detail::WriteField("scenes", io_json, in_document.scenes, alloc);
        detail::WriteField("skins", io_json, in_document.skins, alloc);
        detail::WriteField("textures", io_json, in_document.textures, alloc);
    }

    namespace detail
    {
        struct DataContext
        {
            FX_GLTF_FILESYSTEM::path bufferRootPath{};
            ReadQuotas readQuotas;

            std::vector<uint8_t> * binaryData{};
            std::map<std::string, std::vector<uint8_t>> const* binaryBuffers{};
        };

        inline void ThrowIfBad(std::ios const & io)
        {
            if (!io.good())
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
        }

        inline void MaterializeData(Buffer & buffer)
        {
            std::size_t startPos = 0;
            if (buffer.uri.find(detail::MimetypeApplicationOctet) == 0)
            {
                startPos = std::char_traits<char>::length(detail::MimetypeApplicationOctet) + 1;
            }
            else if (buffer.uri.find(detail::MimetypeGLTFBuffer) == 0)
            {
                startPos = std::char_traits<char>::length(detail::MimetypeGLTFBuffer) + 1;
            }

            const std::size_t base64Length = buffer.uri.length() - startPos;
            const std::size_t decodedEstimate = base64Length / 4 * 3;
            if (startPos == 0 || (decodedEstimate - 2) > buffer.byteLength) // we need to give room for padding...
            {
                throw invalid_gltf_document("Invalid buffer.uri value", "malformed base64");
            }

#if defined(FX_GLTF_HAS_CPP_17)
            const bool success = base64::TryDecode({ &buffer.uri[startPos], base64Length }, buffer.data);
#else
            const bool success = base64::TryDecode(buffer.uri.substr(startPos), buffer.data);
#endif
            if (!success)
            {
                throw invalid_gltf_document("Invalid buffer.uri value", "malformed base64");
            }
        }

        inline Document Create(const rapidjson::Document& in_d, DataContext const & dataContext)
        {
            Document document;
            from_json(in_d, document);

            if (document.buffers.size() > dataContext.readQuotas.MaxBufferCount)
            {
                throw invalid_gltf_document("Quota exceeded : number of buffers > MaxBufferCount");
            }

            for (auto & buffer : document.buffers)
            {
                if (buffer.byteLength == 0)
                {
                    throw invalid_gltf_document("Invalid buffer.byteLength value : 0");
                }

                if (buffer.byteLength > dataContext.readQuotas.MaxBufferByteLength)
                {
                    throw invalid_gltf_document("Quota exceeded : buffer.byteLength > MaxBufferByteLength");
                }

                if (!buffer.uri.empty())
                {
                    if (buffer.IsEmbeddedResource())
                    {
                        detail::MaterializeData(buffer);
                    }
                    else if (dataContext.binaryBuffers->find(buffer.uri) != dataContext.binaryBuffers->cend())
                    {
                        std::vector<uint8_t> const& binary = dataContext.binaryBuffers->at(buffer.uri);
                        buffer.data.resize(buffer.byteLength);
                        std::memcpy(&buffer.data[0], &binary[0], buffer.byteLength);
                    }
                    else
                    {
                        std::ifstream fileData(detail::CreateBufferUriPath(dataContext.bufferRootPath, buffer.uri), std::ios::binary);
                        if (!fileData.good())
                        {
                            throw invalid_gltf_document("Invalid buffer.uri value", buffer.uri);
                        }

                        buffer.data.resize(buffer.byteLength);
                        fileData.read(reinterpret_cast<char *>(&buffer.data[0]), buffer.byteLength);
                    }
                }
                else if (dataContext.binaryData != nullptr)
                {
                    std::vector<uint8_t> & binary = *dataContext.binaryData;
                    if (binary.size() < buffer.byteLength)
                    {
                        throw invalid_gltf_document("Invalid GLB buffer data");
                    }

                    buffer.data.resize(buffer.byteLength);
                    std::memcpy(&buffer.data[0], &binary[0], buffer.byteLength);
                }
            }

            return document;
        }

        inline void ValidateBuffers(Document const & document, bool useBinaryFormat)
        {
            if (document.buffers.empty())
            {
                throw invalid_gltf_document("Invalid glTF document. A document must have at least 1 buffer.");
            }

            bool foundBinaryBuffer = false;
            for (std::size_t bufferIndex = 0; bufferIndex < document.buffers.size(); bufferIndex++)
            {
                Buffer const & buffer = document.buffers[bufferIndex];
                if (buffer.byteLength == 0)
                {
                    throw invalid_gltf_document("Invalid buffer.byteLength value : 0");
                }

                if (buffer.byteLength != buffer.data.size())
                {
                    throw invalid_gltf_document("Invalid buffer.byteLength value : does not match buffer.data size");
                }

                if (buffer.uri.empty())
                {
                    foundBinaryBuffer = true;
                    if (bufferIndex != 0)
                    {
                        throw invalid_gltf_document("Invalid glTF document. Only 1 buffer, the very first, is allowed to have an empty buffer.uri field.");
                    }
                }
            }

            if (useBinaryFormat && !foundBinaryBuffer)
            {
                throw invalid_gltf_document("Invalid glTF document. No buffer found which can meet the criteria for saving to a .glb file.");
            }
        }

        inline void Save(Document const & document, std::ostream & output, FX_GLTF_FILESYSTEM::path const & documentRootPath, bool useBinaryFormat)
        {
            // There is no way to check if an ostream has been opened in binary mode or not. Just checking
            // if it's "good" is the best we can do from here...
            detail::ThrowIfBad(output);

            rapidjson::Document json;
            to_json(json, document);

            std::size_t externalBufferIndex = 0;
            if (useBinaryFormat)
            {
                detail::GLBHeader header{ detail::GLBHeaderMagic, 2, 0, { 0, detail::GLBChunkJSON } };
                detail::ChunkHeader binHeader{ 0, detail::GLBChunkBIN };
                
                rapidjson::StringBuffer sb;
                rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
                json.Accept(writer);
                std::string jsonText = sb.GetString();

                Buffer const & binBuffer = document.buffers.front();
                const uint32_t binPaddedLength = ((binBuffer.byteLength + 3) & (~3u));
                const uint32_t binPadding = binPaddedLength - binBuffer.byteLength;
                binHeader.chunkLength = binPaddedLength;

                header.jsonHeader.chunkLength = ((jsonText.length() + 3) & (~3u));
                const uint32_t headerPadding = static_cast<uint32_t>(header.jsonHeader.chunkLength - jsonText.length());
                header.length = detail::HeaderSize + header.jsonHeader.chunkLength + detail::ChunkHeaderSize + binHeader.chunkLength;

                constexpr std::array<char, 3> spaces = { ' ', ' ', ' ' };
                constexpr std::array<char, 3> nulls = { 0, 0, 0 };

                output.write(reinterpret_cast<char *>(&header), detail::HeaderSize);
                output.write(jsonText.c_str(), jsonText.length());
                output.write(&spaces[0], headerPadding);
                output.write(reinterpret_cast<char *>(&binHeader), detail::ChunkHeaderSize);
                output.write(reinterpret_cast<char const *>(&binBuffer.data[0]), binBuffer.byteLength);
                output.write(&nulls[0], binPadding);

                externalBufferIndex = 1;
            }
            else
            {
                rapidjson::StringBuffer sb;
                rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
                writer.SetIndent(' ', 2);
                json.Accept(writer);
                output << sb.GetString();
            }

            // The glTF 2.0 spec allows a document to have more than 1 buffer. However, only the first one will be included in the .glb
            // All others must be considered as External/Embedded resources. Process them if necessary...
            for (; externalBufferIndex < document.buffers.size(); externalBufferIndex++)
            {
                Buffer const & buffer = document.buffers[externalBufferIndex];
                if (!buffer.IsEmbeddedResource())
                {
                    std::ofstream fileData(detail::CreateBufferUriPath(documentRootPath, buffer.uri), std::ios::binary);
                    if (!fileData.good())
                    {
                        throw invalid_gltf_document("Invalid buffer.uri value", buffer.uri);
                    }

                    fileData.write(reinterpret_cast<char const *>(&buffer.data[0]), buffer.byteLength);
                }
            }
        }
    } // namespace detail

    inline Document LoadFromText(std::istream & input, FX_GLTF_FILESYSTEM::path const & documentRootPath, ReadQuotas const & readQuotas = {}, std::map<std::string, std::vector<uint8_t>> const& binaryBuffers = {})
    {
        try
        {
            detail::ThrowIfBad(input);

            rapidjson::Document       d;
            rapidjson::IStreamWrapper isw(input);
            rapidjson::ParseResult    parseResult = d.ParseStream(isw);

            return detail::Create(d, { documentRootPath, readQuotas, nullptr, &binaryBuffers });
        }
        catch (invalid_gltf_document &)
        {
            throw;
        }
        catch (std::system_error &)
        {
            throw;
        }
        catch (...)
        {
            std::throw_with_nested(invalid_gltf_document("Invalid glTF document. See nested exception for details."));
        }
    }

    inline Document LoadFromText(FX_GLTF_FILESYSTEM::path const & documentFilePath, ReadQuotas const & readQuotas = {})
    {
        std::ifstream input(documentFilePath);
        if (!input.is_open())
        {
            throw std::system_error(std::make_error_code(std::errc::no_such_file_or_directory));
        }

        return LoadFromText(input, detail::GetDocumentRootPath(documentFilePath), readQuotas);
    }

    inline Document LoadFromBinary(std::istream & input, FX_GLTF_FILESYSTEM::path const & documentRootPath, ReadQuotas const & readQuotas = {})
    {
        try
        {
            detail::GLBHeader header{};
            detail::ThrowIfBad(input.read(reinterpret_cast<char *>(&header), detail::HeaderSize));
            if (header.magic != detail::GLBHeaderMagic ||
                header.jsonHeader.chunkType != detail::GLBChunkJSON ||
                header.jsonHeader.chunkLength + detail::HeaderSize > header.length)
            {
                throw invalid_gltf_document("Invalid GLB header");
            }

            std::vector<uint8_t> json{};
            json.resize(header.jsonHeader.chunkLength);
            detail::ThrowIfBad(input.read(reinterpret_cast<char *>(&json[0]), header.jsonHeader.chunkLength));

            std::size_t totalSize = detail::HeaderSize + header.jsonHeader.chunkLength;
            if (totalSize > readQuotas.MaxFileSize)
            {
                throw invalid_gltf_document("Quota exceeded : file size > MaxFileSize");
            }

            detail::ChunkHeader binHeader{};
            detail::ThrowIfBad(input.read(reinterpret_cast<char *>(&binHeader), detail::ChunkHeaderSize));
            if (binHeader.chunkType != detail::GLBChunkBIN)
            {
                throw invalid_gltf_document("Invalid GLB header");
            }

            totalSize += detail::ChunkHeaderSize + binHeader.chunkLength;
            if (totalSize > readQuotas.MaxFileSize)
            {
                throw invalid_gltf_document("Quota exceeded : file size > MaxFileSize");
            }

            std::vector<uint8_t> binary{};
            binary.resize(binHeader.chunkLength);
            detail::ThrowIfBad(input.read(reinterpret_cast<char *>(&binary[0]), binHeader.chunkLength));

            rapidjson::Document    d;
            std::string            jsonStr((const char*) json.data(), header.jsonHeader.chunkLength);
            rapidjson::ParseResult parseResult = d.Parse(jsonStr.data());

            if (parseResult)
            {
                return detail::Create(d, {documentRootPath, readQuotas, &binary});
            }
        }
        catch (invalid_gltf_document &)
        {
            throw;
        }
        catch (std::system_error &)
        {
            throw;
        }
        catch (...)
        {
            std::throw_with_nested(invalid_gltf_document("Invalid glTF document. See nested exception for details."));
        }
        
        return Document();
    }

    inline Document LoadFromBinary(FX_GLTF_FILESYSTEM::path const & documentFilePath, ReadQuotas const & readQuotas = {})
    {
        std::ifstream input(documentFilePath, std::ios::binary);
        if (!input.is_open())
        {
            throw std::system_error(std::make_error_code(std::errc::no_such_file_or_directory));
        }

        return LoadFromBinary(input, detail::GetDocumentRootPath(documentFilePath), readQuotas);
    }

    inline void Save(Document const & document, std::ostream & output, FX_GLTF_FILESYSTEM::path const & documentRootPath, bool useBinaryFormat)
    {
        try
        {
            detail::ValidateBuffers(document, useBinaryFormat);

            detail::Save(document, output, documentRootPath, useBinaryFormat);
        }
        catch (invalid_gltf_document &)
        {
            throw;
        }
        catch (std::system_error &)
        {
            throw;
        }
        catch (...)
        {
            std::throw_with_nested(invalid_gltf_document("Invalid glTF document. See nested exception for details."));
        }
    }

    inline void Save(Document const & document, FX_GLTF_FILESYSTEM::path const & documentFilePath, bool useBinaryFormat)
    {
        std::ofstream output(documentFilePath, useBinaryFormat ? std::ios::binary : std::ios::out);
        Save(document, output, detail::GetDocumentRootPath(documentFilePath), useBinaryFormat);
    }
} // namespace gltf

// A general-purpose utility to format an exception hierarchy into a string for output
inline void FormatException(std::string & output, std::exception const & ex, int level = 0)
{
    output.append(std::string(level, ' ')).append(ex.what());
    try
    {
        std::rethrow_if_nested(ex);
    }
    catch (std::exception const & e)
    {
        FormatException(output.append("\n"), e, level + 2);
    }
}

} // namespace rapidfx

#undef FX_GLTF_HAS_CPP_17
#undef FX_GLTF_NODISCARD
#undef FX_GLTF_INLINE_CONSTEXPR
#undef FX_GLTF_EXPERIMENTAL_FILESYSTEM
#undef FX_GLTF_FILESYSTEM
