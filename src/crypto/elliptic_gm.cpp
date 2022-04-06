#include <fc/crypto/elliptic_gm.hpp>

#include <fc/crypto/base58.hpp>
#include <fc/crypto/openssl.hpp>

#include <fc/fwd_impl.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>

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

    private_key::private_key()
    {}

    private_key private_key::generate_from_seed( const fc::sha256& seed, const fc::sha256& offset )
    {
        ssl_bignum z;
        BN_bin2bn((unsigned char*)&offset, sizeof(offset), z);

        ec_group group(EC_GROUP_new_by_curve_name(NID_sm2p256v1));
        bn_ctx ctx(BN_CTX_new());
        ssl_bignum order;
        EC_GROUP_get_order(group, order, ctx);

        // secexp = (seed + z) % order
        ssl_bignum secexp;
        BN_bin2bn((unsigned char*)&seed, sizeof(seed), secexp);
        BN_add(secexp, secexp, z);
        BN_mod(secexp, secexp, order, ctx);

        fc::sha256 secret;
        FC_ASSERT(BN_num_bytes(secexp) <= int64_t(sizeof(secret)));
        auto shift = sizeof(secret) - BN_num_bytes(secexp);
        BN_bn2bin(secexp, ((unsigned char*)&secret)+shift);
        return regenerate( secret );
    }


    int static inline EC_KEY_regenerate_key(EC_KEY *eckey, const BIGNUM *priv_key)
    {
        int ok = 0;
        BN_CTX *ctx = NULL;
        EC_POINT *pub_key = NULL;

        if (!eckey) return 0;

        const EC_GROUP *group = EC_KEY_get0_group(eckey);

        if ((ctx = BN_CTX_new()) == NULL)
        goto err;

        pub_key = EC_POINT_new(group);

        if (pub_key == NULL)
        goto err;

        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

        EC_KEY_set_private_key(eckey,priv_key);
        EC_KEY_set_public_key(eckey,pub_key);

        ok = 1;

        err:

        if (pub_key) EC_POINT_free(pub_key);
        if (ctx != NULL) BN_CTX_free(ctx);

        return(ok);
    }
    private_key private_key::regenerate( const fc::sha256& secret )
    {
       private_key self;
       self.my->_key = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
       if( !self.my->_key ) FC_THROW_EXCEPTION( exception, "Unable to generate EC key" );

       ssl_bignum bn;
       BN_bin2bn( (const unsigned char*)&secret, 32, bn );

       if( !EC_KEY_regenerate_key(self.my->_key,bn) )
       {
          FC_THROW_EXCEPTION( exception, "unable to regenerate key" );
       }
       return self;
    }

    fc::sha256 private_key::get_secret()const
    {
       if( !my->_key )
       {
          return fc::sha256();
       }

       fc::sha256 sec;
       const BIGNUM* bn = EC_KEY_get0_private_key(my->_key);
       if( bn == NULL )
       {
         FC_THROW_EXCEPTION( exception, "get private key failed" );
       }
       int nbytes = BN_num_bytes(bn);
       BN_bn2bin(bn, &((unsigned char*)&sec)[32-nbytes] );
       return sec;
    }

    private_key private_key::generate()
    {
       private_key self;
       EC_KEY* k = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
       if( !k ) FC_THROW_EXCEPTION( exception, "Unable to generate EC key" );
       self.my->_key = k;
       if( !EC_KEY_generate_key( self.my->_key ) )
       {
          FC_THROW_EXCEPTION( exception, "ecc key generation error" );

       }
       return self;
    }

    signature private_key::sign( const fc::sha256& digest )const
    {
        unsigned int buf_len = ECDSA_size(my->_key);
        signature sig;//already zeroed out by the array initializer
        FC_ASSERT( buf_len > 0 && (buf_len+33)<=105 && (buf_len+33)<=sizeof(sig),"invalid sig length");
        size_t pub_key_len = EC_POINT_point2oct(EC_KEY_get0_group(k), EC_KEY_get0_public_key(k), POINT_CONVERSION_COMPRESSED, &sig, 33, NULL);
        FC_ASSERT(pub_key_len == 33, "invalid pubkey length");

        if (SM2_sign(NID_undef, (const unsigned char*)&digest, sizeof(digest), &sig.data[33], &siglen, my->_key) != 1){
            FC_THROW_EXCEPTION( exception, "signing error" );
        }
        return sig;
    }
    bool public_key::verify( const fc::sha256& digest, const fc::crypto::gm::signature& sig )
    {
      return 1 == SM2_verify( NID_undef, (unsigned char*)&digest, sizeof(digest), (unsigned char*)&sig.data[33], sizeof(sig)-33, my->_key );
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
         my->_key = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
         my->_key = o2i_ECPublicKey( &my->_key, (const unsigned char**)&front, sizeof(public_key_data) );
         if( !my->_key )
         {
           FC_THROW_EXCEPTION( exception, "error decoding public key", ("s", ERR_error_string( ERR_get_error(), nullptr) ) );
         }
      }
    }

    bool       private_key::verify( const fc::sha256& digest, const fc::crypto::gm::signature& sig )
    {
      
      return 1 == SM2_verify( NID_undef, (unsigned char*)&digest, sizeof(digest), (unsigned char*)&sig.data[33], sizeof(sig)-33, my->_key );
    }

    public_key private_key::get_public_key()const
    {
       public_key pub;
       pub.my->_key = EC_KEY_new_by_curve_name( NID_sm2p256v1 );
       EC_KEY_set_public_key( pub.my->_key, EC_KEY_get0_public_key( my->_key ) );
       return pub;
    }


    fc::sha512 private_key::get_shared_secret( const public_key& other )const
    {
      FC_THROW_EXCEPTION(exception, "gm does not support get_shared_secret");
    }

    private_key::~private_key()
    {
    }


    public_key::public_key( const compact_signature& c, const fc::sha256& digest, bool check_canonical )
    {

        const unsigned char *dat = (unsigned char *)&c.data[0];
        uint8_t asn1_enc_length = ((uint8_t)(dat[33 + 1])) + 2;
        FC_ASSERT(asn1_enc_length >= 60 && asn1_enc_length <= 72, "invalid asn1 encoding on signature");
        FC_ASSERT(asn1_enc_length <= (c.size() - 33), "bad match of signature size");
        const unsigned char *front = (uint8_t *)(c.data);
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
        key = o2i_ECPublicKey(&key, (const unsigned char **)&front, 33);
        FC_ASSERT(key, "invalid public key in sm2 signature");
        if (SM2_verify(NID_undef, (uint8_t *)digest.data(), 32, (uint8_t *)&c.data[33], asn1_enc_length, key) == 1)
        {
          const EC_POINT *point = EC_KEY_get0_public_key(key);
          const EC_GROUP *group = EC_KEY_get0_group(key);
          size_t sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, (uint8_t *)&c.data[0], 33, NULL);
          if (sz == 33)
          {
            my->_key = key;
            return;
          }
          FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature p2o" );
        }
        FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature" );
        //FC_THROW_EXCEPTION( exception, "unable to reconstruct public key from signature: ${bytes_sig} - ${bytes_digest}", ("bytes_sig",byte_2_str((char *)(&c.data[0]),105))("bytes_digest",byte_2_str((char *)digest.data(),32))  );
    }

    signature private_key::sign_compact( const fc::sha256& digest )const
    {
      return sign(digest);
    }

   private_key& private_key::operator=( private_key&& pk )
   {
     if( my->_key )
     {
       EC_KEY_free(my->_key);
     }
     my->_key = pk.my->_key;
     pk.my->_key = nullptr;
     return *this;
   }
   public_key::public_key( const public_key& pk )
   :my(pk.my)
   {
   }
   public_key::public_key( public_key&& pk )
   :my( fc::move( pk.my) )
   {
   }
   private_key::private_key( const private_key& pk )
   :my(pk.my)
   {
   }
   private_key::private_key( private_key&& pk )
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
   private_key& private_key::operator=( const private_key& pk )
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
  void to_variant( const crypto::gm::private_key& var,  variant& vo )
  {
    vo = var.get_secret();
  }
  void from_variant( const variant& var,  crypto::gm::private_key& vo )
  {
    fc::sha256 sec;
    from_variant( var, sec );
    vo = crypto::gm::private_key::regenerate(sec);
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
