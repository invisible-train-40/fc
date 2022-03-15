#pragma once
#include <fc/crypto/bigint.hpp>
#include <fc/crypto/common.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/sha512.hpp>
#include <fc/crypto/openssl.hpp>
#include <fc/fwd.hpp>
#include <fc/array.hpp>
#include <fc/io/raw_fwd.hpp>

namespace fc {

  namespace crypto { namespace gm {
    namespace detail
    {
      class public_key_impl;
    }

    typedef fc::array<char,33>          public_key_data;
    typedef fc::array<char,65>          public_key_point_data; ///< the full non-compressed version of the ECC point
    typedef fc::array<char,105>          signature;
    typedef fc::array<unsigned char,105> compact_signature;

    /**
     *  @class public_key
     *  @brief contains only the public point of an elliptic curve key.
     */
    class public_key
    {
        public:
           public_key();
           public_key(const public_key& k);
           ~public_key();
           bool verify( const fc::sha256& digest, const signature& sig );
           public_key_data serialize()const;
           public_key_point_data serialize_ecc_point()const;

           operator public_key_data()const { return serialize(); }


           public_key( const public_key_data& v );
           public_key( const public_key_point_data& v );
           public_key( const compact_signature& c, const fc::sha256& digest, bool check_canonical = true );

           bool valid()const;
           public_key mult( const fc::sha256& offset );
           public_key add( const fc::sha256& offset )const;

           public_key( public_key&& pk );
           public_key& operator=( public_key&& pk );
           public_key& operator=( const public_key& pk );

           inline friend bool operator==( const public_key& a, const public_key& b )
           {
            return a.serialize() == b.serialize();
           }
           inline friend bool operator!=( const public_key& a, const public_key& b )
           {
            return a.serialize() != b.serialize();
           }

           /// Allows to convert current public key object into base58 number.
           std::string to_base58() const;
           static public_key from_base58( const std::string& b58 );

        private:
          fc::fwd<detail::public_key_impl,8> my;
    };


     /**
       * Shims
       */
     struct public_key_shim : public crypto::shim<public_key_data> {
        using crypto::shim<public_key_data>::shim;

        bool valid()const {
           return public_key(_data).valid();
        }
     };

     struct signature_shim : public crypto::shim<compact_signature> {
        using public_key_type = public_key_shim;
        using crypto::shim<compact_signature>::shim;

        public_key_type recover(const sha256& digest, bool check_canonical) const {
           return public_key_type(public_key(_data, digest, check_canonical).serialize());
        }
     };

  } // namespace gm
  } // namespace crypto
  void to_variant( const crypto::gm::public_key& var,  variant& vo );
  void from_variant( const variant& var,  crypto::gm::public_key& vo );

  namespace raw
  {
      template<typename Stream>
      void unpack( Stream& s, fc::crypto::gm::public_key& pk)
      {
          crypto::gm::public_key_data ser;
          fc::raw::unpack(s,ser);
          pk = fc::crypto::gm::public_key( ser );
      }

      template<typename Stream>
      void pack( Stream& s, const fc::crypto::gm::public_key& pk)
      {
          fc::raw::pack( s, pk.serialize() );
      }


  } // namespace raw

} // namespace fc
#include <fc/reflect/reflect.hpp>

FC_REFLECT_TYPENAME( fc::crypto::gm::public_key )
FC_REFLECT_DERIVED( fc::crypto::gm::public_key_shim, (fc::crypto::shim<fc::crypto::gm::public_key_data>), BOOST_PP_SEQ_NIL )
FC_REFLECT_DERIVED( fc::crypto::gm::signature_shim, (fc::crypto::shim<fc::crypto::gm::compact_signature>), BOOST_PP_SEQ_NIL )
