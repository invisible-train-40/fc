#include <fc/crypto/elliptic_gm.hpp>
#include <fc/crypto/elliptic_r1.hpp>
#include <fc/crypto/base58.hpp>
#include <fc/crypto/openssl.hpp>

#include <fc/fwd_impl.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/opensslconf.h>
#define SIG_OFFSET_IN_GM_SIGNATURE 33

#include <string>
namespace fc
{
  namespace crypto
  {
    namespace gm
    {
      namespace detail
      {
        class public_key_impl
        {
        public:
          public_key_impl()
              : _key(nullptr)
          {
            init_openssl();
          }

          ~public_key_impl()
          {
            if (_key != nullptr)
            {
              EC_KEY_free(_key);
            }
          }
          public_key_impl(const public_key_impl &cpy)
          {
            _key = cpy._key ? EC_KEY_dup(cpy._key) : nullptr;
          }
          EC_KEY *_key;
        };
        class private_key_impl
        {
        public:
          private_key_impl()
              : _key(nullptr)
          {
            init_openssl();
          }
          ~private_key_impl()
          {
            if (_key != nullptr)
            {
              EC_KEY_free(_key);
            }
          }
          private_key_impl(const private_key_impl &cpy)
          {
            _key = cpy._key ? EC_KEY_dup(cpy._key) : nullptr;
          }
          EC_KEY *_key;
        };
      }

      public_key_data_type public_key::serialize() const
      {
        public_key_data_type dat;
        if (!my->_key)
          return dat;
        EC_KEY_set_conv_form(my->_key, POINT_CONVERSION_COMPRESSED);
        /*size_t nbytes = i2o_ECPublicKey( my->_key, nullptr ); */
        /*FC_ASSERT( nbytes == 33 )*/
        char *front = &dat.data[0];
        i2o_ECPublicKey(my->_key, (unsigned char **)&front);
        return dat;
        /*
         EC_POINT* pub   = EC_KEY_get0_public_key( my->_key );
         EC_GROUP* group = EC_KEY_get0_group( my->_key );
         EC_POINT_get_affine_coordinates_GFp( group, pub, self.my->_pub_x.get(), self.my->_pub_y.get(), nullptr );
         */
      }
      public_key_point_data public_key::serialize_ecc_point() const
      {
        public_key_point_data dat;
        if (!my->_key)
          return dat;
        EC_KEY_set_conv_form(my->_key, POINT_CONVERSION_UNCOMPRESSED);
        char *front = &dat.data[0];
        i2o_ECPublicKey(my->_key, (unsigned char **)&front);
        return dat;
      }

      public_key::public_key()
      {
      }
      public_key::~public_key()
      {
      }
      public_key::public_key(const gm::signature &c, const fc::sha256 &digest, bool)
      {
        uint8_t asn1_enc_length = ((uint8_t)(c.sm2_signature_asn1.data[1])) + 2;
        FC_ASSERT(asn1_enc_length >= 70 && asn1_enc_length <= 72, "invalid asn1 encoding on signature");
        FC_ASSERT(asn1_enc_length == c.sm2_signature_asn1.size(), "bad match of signature size");
        unsigned char *front = (uint8_t *)(c.pub_key.data);
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
        key = o2i_ECPublicKey(&key, (const unsigned char **)&front, c.pub_key.size());
        FC_ASSERT(key, "invalid public key in sm2 signature");
        if (SM2_verify(NID_undef, (uint8_t *)digest.data(), 32, (uint8_t *)&c.sm2_signature_asn1.data[0], c.sm2_signature_asn1.size(), key) == 1)
        {
          const EC_POINT *point = EC_KEY_get0_public_key(key);
          const EC_GROUP *group = EC_KEY_get0_group(key);
          size_t sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, front, 33, NULL);
          if (sz == 33)
          {
            my->_key = key;
            return;
          }
        }

        FC_THROW_EXCEPTION(exception, "unable to reconstruct public key from signature");
      }

      std::string public_key::to_base58() const
      {
        public_key_data_type key = serialize();
        uint32_t check = (uint32_t)sha256::hash(key.data, sizeof(key))._hash[0];
        static_assert(sizeof(key) + sizeof(check) == 37, ""); // hack around gcc bug: key.size() should be constexpr, but isn't
        array<char, 37> data;
        memcpy(data.data, key.begin(), key.size());
        memcpy(data.begin() + key.size(), (const char *)&check, sizeof(check));
        return fc::to_base58(data.begin(), data.size(), fc::yield_function_t());
      }

      public_key public_key::from_base58(const std::string &b58)
      {
        array<char, 37> data;
        size_t s = fc::from_base58(b58, (char *)&data, sizeof(data));
        FC_ASSERT(s == sizeof(data));

        public_key_data_type key;
        uint32_t check = (uint32_t)sha256::hash(data.data, sizeof(key))._hash[0];
        FC_ASSERT(memcmp((char *)&check, data.data + sizeof(key), sizeof(check)) == 0);
        memcpy((char *)key.data, data.data, sizeof(key));
        return public_key(key);
      }
      public_key::public_key(const gm::sig_type &c, const fc::sha256 &digest, bool)
      {
        const unsigned char *dat = (unsigned char *)&c.data[0];
        uint8_t asn1_enc_length = ((uint8_t)(dat[SIG_OFFSET_IN_GM_SIGNATURE + 1])) + 2;
        FC_ASSERT(asn1_enc_length >= 70 && asn1_enc_length <= 72, "invalid asn1 encoding on signature");
        FC_ASSERT(asn1_enc_length == (c.size() - 33), "bad match of signature size");
        const unsigned char *front = (uint8_t *)(c.data);
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
        key = o2i_ECPublicKey(&key, (const unsigned char **)&front, 33);
        FC_ASSERT(key, "invalid public key in sm2 signature");
        if (SM2_verify(NID_undef, (uint8_t *)digest.data(), 32, (uint8_t *)&c.data[SIG_OFFSET_IN_GM_SIGNATURE], (c.size() - 33), key) == 1)
        {
          const EC_POINT *point = EC_KEY_get0_public_key(key);
          const EC_GROUP *group = EC_KEY_get0_group(key);
          size_t sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, (uint8_t *)&c.data[0], 33, NULL);
          if (sz == 33)
          {
            my->_key = key;
            return;
          }
        }

        FC_THROW_EXCEPTION(exception, "unable to reconstruct public key from signature");
      }
    public_key::public_key( const public_key_point_data& dat )
    {
      const char* front = &dat.data[0];
      if( *front == 0 ){}
      else
      {
         my->_key = o2i_ECPublicKey( &my->_key, (const unsigned char**)&front, sizeof(dat)  );
         if( !my->_key )
         {
           FC_THROW_EXCEPTION( exception, "error decoding public key", ("s", ERR_error_string( ERR_get_error(), nullptr) ) );
         }
      }
    }
    public_key::public_key( const public_key_data_type& dat )
    {
      const char* front = &dat.data[0];
      if( *front == 0 ){}
      else
      {
         my->_key = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
         my->_key = o2i_ECPublicKey( &my->_key, (const unsigned char**)&front, sizeof(public_key_data_type) );
         if( !my->_key )
         {
           FC_THROW_EXCEPTION( exception, "error decoding public key", ("s", ERR_error_string( ERR_get_error(), nullptr) ) );
         }
      }
    }

    }
  }

  void to_variant(const crypto::gm::public_key &var, variant &vo)
  {
    vo = var.serialize();
  }
  void from_variant(const variant &var, crypto::gm::public_key &vo)
  {
    crypto::gm::public_key_data_type dat;
    from_variant(var, dat);
    vo = crypto::gm::public_key(dat);
  }
}