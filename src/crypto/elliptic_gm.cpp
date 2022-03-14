#include <fc/crypto/elliptic_gm.hpp>
#include <fc/crypto/elliptic_r1.hpp>
#include <fc/crypto/base58.hpp>
#include <fc/crypto/openssl.hpp>

#include <fc/fwd_impl.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/sm2.h>
#include <openssl/opensslconf.h>


#include <string>

static int check_sm2_signature(const unsigned char * pub_key, size_t pub_key_length, const unsigned char * signature, const unsigned char * signature_length, const unsigned char * digest_32) {
  const unsigned char* front = pub_key;
  EC_KEY * key = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
  key = o2i_ECPublicKey( &key, (const unsigned char**)&front, pub_key_length );
	if(!key){
		return -1;
  }
	if(SM2_verify(NID_undef, digest_32, 32, signature, signature_length, key)==1){
		return 1;
	}
	return -2;
}
namespace fc { namespace crypto { namespace gm {
    namespace detail
    {
      class public_key_impl
      {
        public:
          public_key_impl()
          :_key(nullptr)
          {
            init_openssl();
          }

          ~public_key_impl()
          {
            if( _key != nullptr )
            {
              EC_KEY_free(_key);
            }
          }
          public_key_impl( const public_key_impl& cpy )
          {
            _key = cpy._key ? EC_KEY_dup( cpy._key ) : nullptr;
          }
          EC_KEY* _key;
      };
      class private_key_impl
      {
        public:
          private_key_impl()
          :_key(nullptr)
          {
            init_openssl();
          }
          ~private_key_impl()
          {
            if( _key != nullptr )
            {
              EC_KEY_free(_key);
            }
          }
          private_key_impl( const private_key_impl& cpy )
          {
            _key = cpy._key ? EC_KEY_dup( cpy._key ) : nullptr;
          }
          EC_KEY* _key;
      };
    }


public_key::public_key(const signature& c, const fc::sha256& digest, bool) {
    uint8_t asn1_enc_length = ((uint8_t)(c.sm2_signature_asn1.data[1])) + 2;
    FC_ASSERT(asn1_enc_length>=70&&asn1_enc_length<=72, "invalid asn1 encoding on signature");
    FC_ASSERT(asn1_enc_length==c.sm2_signature_asn1.size(), "bad match of signature size");
    const unsigned char* front = (uint8_t *)(c.pub_key.data);
    EC_KEY * key = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
    key = o2i_ECPublicKey( &key, (const unsigned char**)&front, c.pub_key.size() );
    FC_ASSERT(key, "invalid public key in sm2 signature");
    if(SM2_verify(NID_undef, (uint8_t *)digest.data, 32, (uint8_t *)c.sm2_signature_asn1.data, c.sm2_signature_asn1.size(), key)==1){
      const EC_POINT* point = EC_KEY_get0_public_key(key);
      const EC_GROUP* group = EC_KEY_get0_group(key);
      size_t sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, (uint8_t*)public_key_data.data, public_key_data.size(), NULL);
      if(sz == public_key_data.size()){
        return;
      }
    }

   FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );
}


}}

  void to_variant( const crypto::gm::public_key& var,  variant& vo )
  {
    vo = var.serialize();
  }
  void from_variant( const variant& var,  crypto::gm::public_key& vo )
  {
    crypto::gm::public_key_data dat;
    from_variant( var, dat );
    vo = 
}