#include <fc/crypto/elliptic_gm.hpp>

#include <fc/crypto/base58.hpp>
#include <fc/crypto/openssl.hpp>

#include <fc/fwd_impl.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>
#define SIG_OFFSET_IN_GM_SIGNATURE 33

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
    }
    static void * ecies_key_derivation(const void *input, size_t ilen, void *output, size_t *olen)
    {
        if (*olen < SHA512_DIGEST_LENGTH) {
          return NULL;
        }
        *olen = SHA512_DIGEST_LENGTH;
        return (void*)SHA512((const unsigned char*)input, ilen, (unsigned char*)output);
    }

    // Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
    // recid selects which key is recovered
    // if check is non-zero, additional checks are performed
    int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
    {
        if (!eckey) FC_THROW_EXCEPTION( exception, "null key" );

        int ret = 0;
        BN_CTX *ctx = NULL;

        BIGNUM *x = NULL;
        BIGNUM *e = NULL;
        BIGNUM *order = NULL;
        BIGNUM *sor = NULL;
        BIGNUM *eor = NULL;
        BIGNUM *field = NULL;
        EC_POINT *R = NULL;
        EC_POINT *O = NULL;
        EC_POINT *Q = NULL;
        BIGNUM *rr = NULL;
        BIGNUM *zero = NULL;
        int n = 0;
        int i = recid / 2;

        const BIGNUM *r, *s;
        ECDSA_SIG_get0(ecsig, &r, &s);

        const EC_GROUP *group = EC_KEY_get0_group(eckey);
        if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
        BN_CTX_start(ctx);
        order = BN_CTX_get(ctx);
        if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
        x = BN_CTX_get(ctx);
        if (!BN_copy(x, order)) { ret=-1; goto err; }
        if (!BN_mul_word(x, i)) { ret=-1; goto err; }
        if (!BN_add(x, x, r)) { ret=-1; goto err; }
        field = BN_CTX_get(ctx);
        if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
        if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
        if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
        if (check)
        {
            if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
            if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
            if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
        }
        if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        n = EC_GROUP_get_degree(group);
        e = BN_CTX_get(ctx);
        if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
        if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
        zero = BN_CTX_get(ctx);
        if (!BN_zero(zero)) { ret=-1; goto err; }
        if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
        rr = BN_CTX_get(ctx);
        if (!BN_mod_inverse(rr, r, order, ctx)) { ret=-1; goto err; }
        sor = BN_CTX_get(ctx);
        if (!BN_mod_mul(sor, s, rr, order, ctx)) { ret=-1; goto err; }
        eor = BN_CTX_get(ctx);
        if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
        if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
        if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

        ret = 1;

    err:
        if (ctx) {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }
        if (R != NULL) EC_POINT_free(R);
        if (O != NULL) EC_POINT_free(O);
        if (Q != NULL) EC_POINT_free(Q);
        return ret;
    }


/*
    public_key::public_key()
    :my( new detail::public_key_impl() )
    {
    }

    public_key::public_key( fc::bigint pub_x, fc::bigint pub_y )
    :my( new detail::public_key_impl() )
    {
    }

    public_key::~public_key()
    {
    }
    */

    bool       public_key::valid()const
    {
      return my->_key != nullptr;
    }

    std::string public_key::to_base58() const
    {
      public_key_data key = serialize();
      uint32_t check = (uint32_t)sha256::hash(key.data, sizeof(key))._hash[0];
      static_assert(sizeof(key) + sizeof(check) == 37, ""); // hack around gcc bug: key.size() should be constexpr, but isn't
      array<char, 37> data;
      memcpy(data.data, key.begin(), key.size());
      memcpy(data.begin() + key.size(), (const char*)&check, sizeof(check));
      return fc::to_base58(data.begin(), data.size(), fc::yield_function_t());
    }

    public_key public_key::from_base58( const std::string& b58 )
    {
        array<char, 37> data;
        size_t s = fc::from_base58(b58, (char*)&data, sizeof(data) );
        FC_ASSERT( s == sizeof(data) );

        public_key_data key;
        uint32_t check = (uint32_t)sha256::hash(data.data, sizeof(key))._hash[0];
        FC_ASSERT( memcmp( (char*)&check, data.data + sizeof(key), sizeof(check) ) == 0 );
        memcpy( (char*)key.data, data.data, sizeof(key) );
        return public_key(key);
    }

    bool       public_key::verify( const fc::sha256& digest, const fc::crypto::gm::signature& sig )
    {
      return 1 == ECDSA_verify( 0, (unsigned char*)&digest, sizeof(digest), (unsigned char*)&sig, sizeof(sig), my->_key );
    }

    public_key_data public_key::serialize()const
    {
      public_key_data dat;
      if( !my->_key ) return dat;
      EC_KEY_set_conv_form( my->_key, POINT_CONVERSION_COMPRESSED );
      /*size_t nbytes = i2o_ECPublicKey( my->_key, nullptr ); */
      /*FC_ASSERT( nbytes == 33 )*/
      char* front = &dat.data[0];
      i2o_ECPublicKey( my->_key, (unsigned char**)&front  );
      return dat;
      /*
       EC_POINT* pub   = EC_KEY_get0_public_key( my->_key );
       EC_GROUP* group = EC_KEY_get0_group( my->_key );
       EC_POINT_get_affine_coordinates_GFp( group, pub, self.my->_pub_x.get(), self.my->_pub_y.get(), nullptr );
       */
    }
    public_key_point_data public_key::serialize_ecc_point()const
    {
      public_key_point_data dat;
      if( !my->_key ) return dat;
      EC_KEY_set_conv_form( my->_key, POINT_CONVERSION_UNCOMPRESSED );
      char* front = &dat.data[0];
      i2o_ECPublicKey( my->_key, (unsigned char**)&front  );
      return dat;
    }

    public_key::public_key()
    {
    }
    public_key::~public_key()
    {
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
    public_key::public_key( const public_key_data& dat )
    {
      const char* front = &dat.data[0];
      if( *front == 0 ){}
      else
      {
         my->_key = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
         my->_key = o2i_ECPublicKey( &my->_key, (const unsigned char**)&front, sizeof(public_key_data) );
         if( !my->_key )
         {
           FC_THROW_EXCEPTION( exception, "error decoding public key", ("s", ERR_error_string( ERR_get_error(), nullptr) ) );
         }
      }
    }
/*
      public_key::public_key(const fc::crypto::gm::signature &c, const fc::sha256 &digest, bool)
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
      public_key::public_key(const fc::crypto::gm::sig_type &c, const fc::sha256 &digest, bool)
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
      }*/


    public_key::public_key( const compact_signature& c, const fc::sha256& digest, bool check_canonical )
    {
        int nV = c.data[0];
        if (nV<27 || nV>=35)
            FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );

        ecdsa_sig sig = ECDSA_SIG_new();
        BIGNUM *r = BN_new(), *s = BN_new();
        BN_bin2bn(&c.data[1],32,r);
        BN_bin2bn(&c.data[33],32,s);
        ECDSA_SIG_set0(sig, r, s);

        my->_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        const EC_GROUP* group = EC_KEY_get0_group(my->_key);
        ssl_bignum order, halforder;
        EC_GROUP_get_order(group, order, nullptr);
        BN_rshift1(halforder, order);
        if(BN_cmp(s, halforder) > 0)
           FC_THROW_EXCEPTION( exception, "invalid high s-value encountered in r1 signature" );

        if (nV >= 31)
        {
            EC_KEY_set_conv_form( my->_key, POINT_CONVERSION_COMPRESSED );
            nV -= 4;
//            fprintf( stderr, "compressed\n" );
        }

        if (ECDSA_SIG_recover_key_GFp(my->_key, sig, (unsigned char*)&digest, sizeof(digest), nV - 27, 0) == 1)
            return;
        FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );
    }

   public_key::public_key( const public_key& pk )
   :my(pk.my)
   {
   }
   public_key::public_key( public_key&& pk )
   :my( fc::move( pk.my) )
   {
   }

   public_key& public_key::operator=( public_key&& pk )
   {
     if( my->_key )
     {
       EC_KEY_free(my->_key);
     }
     my->_key = pk.my->_key;
     pk.my->_key = nullptr;
     return *this;
   }
   public_key& public_key::operator=( const public_key& pk )
   {
     if( my->_key )
     {
       EC_KEY_free(my->_key);
     }
     my->_key = EC_KEY_dup(pk.my->_key);
     return *this;
   }

}
}
  void to_variant( const crypto::gm::public_key& var,  variant& vo )
  {
    vo = var.serialize();
  }
  void from_variant( const variant& var,  crypto::gm::public_key& vo )
  {
    crypto::gm::public_key_data dat;
    from_variant( var, dat );
    vo = crypto::gm::public_key(dat);
  }


}
