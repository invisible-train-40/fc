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

        //if (ECDSA_SIG_recover_key_GFp(my->_key, sig, (unsigned char*)&digest, sizeof(digest), nV - 27, 0) == 1)
        //    return;
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
