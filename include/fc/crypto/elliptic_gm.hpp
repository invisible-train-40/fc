#pragma once
#include <fc/crypto/bigint.hpp>
#include <fc/crypto/common.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/elliptic_r1.hpp>
#include <fc/crypto/openssl.hpp>
#include <fc/fwd.hpp>
#include <fc/array.hpp>
#include <fc/io/raw_fwd.hpp>

namespace fc { namespace crypto { namespace gm {

   class signature;
   class public_key;

    namespace detail
    {
      class public_key_impl;
    }
    typedef fc::array<char,72>          sm2_signature_base;
    typedef fc::array<char,33>          public_key_data_type;
    typedef fc::array<char,65>          public_key_point_data; ///< the full non-compressed version of the ECC point
    typedef fc::array<char,105>         sig_type;

     struct public_key_shim : public crypto::shim<gm::public_key_data_type> {
        using crypto::shim<gm::public_key_data_type>::shim;
        
        bool valid()const {
           return public_key(_data).valid();
        }
     };

    /**
     *  @class public_key
     *  @brief contains only the public point of an elliptic curve key.
     */
    class public_key
    {
       
        public:
         using public_key_data_type = fc::array<char, 33>;

         //Used for base58 de/serialization
         using data_type = public_key;
           public_key();
           public_key(const public_key& k);
           ~public_key();
           bool verify( const fc::sha256& digest, const signature& sig );
           public_key_data_type serialize()const;
           public_key_point_data serialize_ecc_point()const;

           operator public_key_data_type()const { return serialize(); }

           public_key( const  fc::crypto::gm::public_key_shim& v);
           public_key( const public_key_data_type& v );
           public_key( const public_key_point_data& v );
           public_key( const signature& c, const fc::sha256& digest, bool check_canonical = true );
           public_key( const sig_type& c, const fc::sha256& digest, bool check_canonical = true );

           bool valid()const;

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

class signature {
   public:
      //used for base58 de/serialization
      using data_type = signature;
      signature serialize()const { return *this; }

      signature() {}
      signature(const gm::public_key_data_type& s, const gm::sm2_signature_base& a) :
         pub_key(s), sm2_signature_asn1(a) {}

      public_key recover(const sha256& digest, bool check_canonical) const {
         return public_key(*this, digest, check_canonical);
      }
      size_t variable_size() const {
         return 105;
      }

      bool operator==(const signature& o) const {
         return pub_key == o.pub_key &&
                  sm2_signature_asn1 == o.sm2_signature_asn1;
      }

      bool operator<(const signature& o) const {
         return std::tie(pub_key, sm2_signature_asn1) < std::tie(pub_key, sm2_signature_asn1);
      }

      //for container usage
      size_t get_hash() const {
         return *(size_t*)&sm2_signature_asn1.data[32-sizeof(size_t)] + *(size_t*)&sm2_signature_asn1.data[64-sizeof(size_t)];
      }

      friend struct fc::reflector<signature>;
      friend class public_key;
   private:
      gm::public_key_data_type pub_key;
      gm::sm2_signature_base sm2_signature_asn1;
};

     /**
       * Shims
       */

   
     


     struct signature_shim : public crypto::shim<gm::sig_type> {
        using public_key_type = public_key_shim;
        using crypto::shim<gm::sig_type>::shim;

        public_key_type recover(const sha256& digest, bool check_canonical) const {
           return public_key_type(public_key(_data, digest, check_canonical).serialize());
        }
     };
}

template<>
struct eq_comparator<gm::signature> {
   static bool apply(const gm::signature& a, const gm::signature& b) {
      return a == b;
   }
};

template<>
struct less_comparator<gm::signature> {
   static bool apply(const gm::signature& a, const gm::signature& b) {
      return a < b;
   }
};

}

  void to_variant( const crypto::gm::public_key& var,  variant& vo );
  void from_variant( const variant& var,  crypto::gm::public_key& vo );

  namespace raw
  {
      template<typename Stream>
      void unpack( Stream& s, fc::crypto::gm::public_key& pk)
      {
          crypto::gm::public_key_data_type ser;
          fc::raw::unpack(s,ser);
          pk = fc::crypto::gm::public_key( ser );
      }

      template<typename Stream>
      void pack( Stream& s, const fc::crypto::gm::public_key& pk)
      {
          fc::raw::pack( s, pk.serialize() );
      }


  } // namespace raw
}
#include <fc/reflect/reflect.hpp>

FC_REFLECT(fc::crypto::gm::signature, (pub_key)(sm2_signature_asn1))
FC_REFLECT_TYPENAME( fc::crypto::gm::public_key )
FC_REFLECT_DERIVED( fc::crypto::gm::public_key_shim, (fc::crypto::shim<fc::crypto::gm::public_key_data_type>), BOOST_PP_SEQ_NIL )
FC_REFLECT_DERIVED( fc::crypto::gm::signature_shim, (fc::crypto::shim<fc::crypto::gm::sig_type>), BOOST_PP_SEQ_NIL )
