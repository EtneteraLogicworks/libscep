/* src/scep.c */

#include "scep.h"

/* Global variables to track global state */
static SCEP_OIDS *_scep_oids = NULL;
static int _scep_handle_count = 0;

SCEP_ERROR scep_init(SCEP **handle)
{
	SCEP *local_handle;
	SCEP_ERROR error;

	// globally run once
	if(_scep_handle_count == 0) {
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();
	}
	if(!(local_handle = malloc(sizeof(SCEP))))
		return SCEPE_MEMORY;
	memset(local_handle, 0, sizeof(SCEP));
	if((error = scep_conf_init(local_handle)) != SCEPE_OK)
	{
		scep_cleanup(local_handle);
		return error;
	}

	if((error = scep_create_oids(local_handle))) {
		scep_cleanup(local_handle);
		return error;
	}

	_scep_handle_count += 1;
	*handle = local_handle;
	return SCEPE_OK;
}

void scep_cleanup(SCEP *handle)
{
	scep_conf_free(handle->configuration); // calls ENGINE_cleanup();
	_scep_handle_count -= 1;
	// globally run once
	if(_scep_handle_count == 0) {
		free(_scep_oids);
		_scep_oids = NULL;
		// https://wiki.openssl.org/index.php/Library_Initialization#Cleanup
		CONF_modules_unload(1);         // all modules, including builtin modules will be unloaded
		EVP_cleanup();                  // removes all digests and ciphers
		CRYPTO_cleanup_all_ex_data();   // needed if BIOs were used
#if OPENSSL_VERSION_NUMBER < 0x10000000L
		ERR_remove_state();
#endif
		ERR_free_strings();             // free all previously loaded error strings (no-op in OpenSSL > v1.1.0)
		OBJ_cleanup();                  // clean up OpenSSLs internal object table (if OBJ_create was called)
	}
	free(handle);
}

SCEP_ERROR scep_create_oids(SCEP *handle)
{
	if(_scep_oids == NULL) {
		_scep_oids = malloc(sizeof(SCEP_OIDS));
		if(!_scep_oids)
			return SCEPE_MEMORY;
		memset(_scep_oids, 0, sizeof(SCEP_OIDS));

		#if 0
		    if (ERR_GET_REASON(ERR_peek_error()) != OBJ_R_OID_EXISTS) {
		      ERR_print_errors(handle->configuration->log);
		      scep_log(handle, FATAL, "Could not create new OID \"messageType\"");
		      return SCEPE_OPENSSL;
		    } else 
		      ERR_clear_error();
		  }
#endif
		
		_scep_oids->messageType = OBJ_txt2nid("messageType");
		if (_scep_oids->messageType == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->messageType = OBJ_create("2.16.840.1.113733.1.9.2", "messageType", "messageType");
		  if(_scep_oids->messageType == 0) {
		      ERR_print_errors(handle->configuration->log);
		      scep_log(handle, FATAL, "Could not create new OID \"messageType\"");
		      return SCEPE_OPENSSL;
		  }
		}

		_scep_oids->pkiStatus = OBJ_txt2nid("pkiStatus");
		if (_scep_oids->pkiStatus == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->pkiStatus = OBJ_create("2.16.840.1.113733.1.9.3", "pkiStatus", "pkiStatus");
		  if(_scep_oids->pkiStatus == 0) {
		    ERR_print_errors(handle->configuration->log);
		    scep_log(handle, FATAL, "Could not create new OID \"pkiStatus\"");
		    return SCEPE_OPENSSL;
		  }
		}

		_scep_oids->failInfo = OBJ_txt2nid("failInfo");
		if (_scep_oids->failInfo == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->failInfo = OBJ_create("2.16.840.1.113733.1.9.4", "failInfo", "failInfo");
		  if(_scep_oids->failInfo == 0) {
		    ERR_print_errors(handle->configuration->log);
		    scep_log(handle, FATAL, "Could not create new OID \"failInfo\"");
		    return SCEPE_OPENSSL;
		  }
		}
		
		_scep_oids->senderNonce = OBJ_txt2nid("senderNonce");
		if (_scep_oids->senderNonce == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->senderNonce = OBJ_create(
			"2.16.840.1.113733.1.9.5", "senderNonce", "senderNonce");
		  if(_scep_oids->senderNonce == 0) {
		    ERR_print_errors(handle->configuration->log);
		    scep_log(handle, FATAL, "Could not create new OID \"senderNonce\"");
		    return SCEPE_OPENSSL;
		  }
		}

		_scep_oids->recipientNonce = OBJ_txt2nid("recipientNonce");
		if (_scep_oids->recipientNonce == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->recipientNonce = OBJ_create("2.16.840.1.113733.1.9.6", "recipientNonce", "recipientNonce");
		  if(_scep_oids->recipientNonce == 0) {
		    ERR_print_errors(handle->configuration->log);
		    scep_log(handle, FATAL, "Could not create new OID \"recipientNonce\"");
		    return SCEPE_OPENSSL;
		  }
		}

		_scep_oids->transId = OBJ_txt2nid("transId");
		if (_scep_oids->transId == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->transId = OBJ_create("2.16.840.1.113733.1.9.7", "transId", "transId");
		  if(_scep_oids->transId == 0) {
		    ERR_print_errors(handle->configuration->log);
		    scep_log(handle, FATAL, "Could not create new OID \"transId\"");
		    return SCEPE_OPENSSL;
		  }
		}

		_scep_oids->extensionReq = OBJ_txt2nid("extensionReq");
		if (_scep_oids->extensionReq == 0) {
		  // OID does not exist (yet, create it)
		  _scep_oids->extensionReq = OBJ_create(
							"2.16.840.1.113733.1.9.8", "extensionReq", "extensionReq");
		  if(_scep_oids->extensionReq == 0) {
		    ERR_print_errors(handle->configuration->log);
		    scep_log(handle, FATAL, "Could not create new OID \"extensionReq\"");
		    return SCEPE_OPENSSL;
		  }
		}
	}
	handle->oids = _scep_oids;
	return SCEPE_OK;
}

SCEP_ERROR scep_param_set(SCEP *handle, SCEP_PARAM type, void *value)
{
	switch(type)
	{
		case SCEP_PARAM_SENDERNONCE:
			if(!memcpy(handle->senderNonce, (char *)value, NONCE_LENGTH))
				return SCEPE_PARAM;
			break;
	}

	handle->params_set |= type;
	return SCEPE_OK;
}

SCEP_ERROR scep_param_get(SCEP *handle, SCEP_PARAM type, void **value)
{
	if(!(handle->params_set & type)) {
		scep_log(handle, ERROR, "Parameter %d has not been set", type);
		return SCEPE_PARAM;
	}

	switch(type)
	{
		case SCEP_PARAM_SENDERNONCE:
			memcpy((char *)value, handle->senderNonce, NONCE_LENGTH);
			break;
	}

	return SCEPE_OK;
}
