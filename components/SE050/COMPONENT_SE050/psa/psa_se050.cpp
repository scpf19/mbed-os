/*******************************************************************************
 *  _____       ______   ____
 * |_   _|     |  ____|/ ____|  Institute of Embedded Systems
 *   | |  _ __ | |__  | (___    Internet of Things Group
 *   | | | '_ \|  __|  \___ \   Zuercher Hochschule Winterthur
 *  _| |_| | | | |____ ____) |  (University of Applied Sciences)
 * |_____|_| |_|______|_____/   8401 Winterthur, Switzerland
 *
 *******************************************************************************
 *
 * Copyright (c) 2018, Institute Of Embedded Systems at Zurich University
 * of Applied Sciences. All rights reserved.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *****************************************************************************
 * \file        psa_se050.cpp
 *
 * \description Module implements a set of cryptographic operations using the 
 *              SE050 and provides these function for the SE driver in the TF-M.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        09.12.2019
 *
 *****************************************************************************/
#include "mbed.h"

#include "psa_se050.h"
#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "error.h"

/* SE050 includes */
#include "fsl_sss_api.h"
#include "nxScp03_Types.h"
#include "ax_reset.h"
#include "sm_timer.h"

#include "mbedtls/platform.h"

#define CA_CERTIFICATE                                                  \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIICrDCCAlKgAwIBAgICEAAwCgYIKoZIzj0EAwIwga0xCzAJBgNVBAYTAkNIMRQw\r\n"  \
"EgYDVQQIDAtTd2l0emVybGFuZDEOMAwGA1UEBwwFVXp3aWwxHzAdBgNVBAoMFkVt\r\n"  \
"YmVkZGVkIFNlY3VyaXR5IEdtYkgxFjAUBgNVBAsMDVRlYW0gU2VjdXJpdHkxEjAQ\r\n"  \
"BgNVBAMMCU1hc3Rlcl9DQTErMCkGCSqGSIb3DQEJARYcdG9iaWFzLnNjaGxhZXBm\r\n"  \
"ZXJAYmx1ZXdpbi5jaDAeFw0xOTA5MDYwNjM4NTNaFw0yOTA5MDMwNjM4NTNaMIGn\r\n"  \
"MQswCQYDVQQGEwJDSDEUMBIGA1UECAwLU3dpdHplcmxhbmQxHzAdBgNVBAoMFkVt\r\n"  \
"YmVkZGVkIFNlY3VyaXR5IEdtYkgxFjAUBgNVBAsMDVRlYW0gU2VjdXJpdHkxHDAa\r\n"  \
"BgNVBAMME01hc3Rlcl9JbnRlcm1lZGlhdGUxKzApBgkqhkiG9w0BCQEWHHRvYmlh\r\n"  \
"cy5zY2hsYWVwZmVyQGJsdWV3aW4uY2gwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\r\n"  \
"AATkzilFhtS6EVs0AS95Ct+NKQvpq3ljVbnlsTpfqZ9Coqeq+BOQ4sZOLthutlYc\r\n"  \
"O8cubR6WzUuINZQxyaPB/7yro2YwZDAdBgNVHQ4EFgQUJXJuI/jYEfCh/4gpAMv0\r\n"  \
"c39JW5AwHwYDVR0jBBgwFoAUFjdDUMu1TXi3TDKyhdLmoYgBBugwEgYDVR0TAQH/\r\n"  \
"BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIhAIWj\r\n"  \
"sVXfABLq8PDwBXxrlvEdV0M49sFi4fOI3zlRy62eAiAc8O77aTmTfCRwBvOfmjQZ\r\n"  \
"UEP8TWEj946WZAKQrdnZxg==\r\n"                                          \
"-----END CERTIFICATE-----\r\n"                                         \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIICwjCCAmegAwIBAgIUXQXeFB2YpaTKg5MqFBtT5x2GA6IwCgYIKoZIzj0EAwIw\r\n"  \
"ga0xCzAJBgNVBAYTAkNIMRQwEgYDVQQIDAtTd2l0emVybGFuZDEOMAwGA1UEBwwF\r\n"  \
"VXp3aWwxHzAdBgNVBAoMFkVtYmVkZGVkIFNlY3VyaXR5IEdtYkgxFjAUBgNVBAsM\r\n"  \
"DVRlYW0gU2VjdXJpdHkxEjAQBgNVBAMMCU1hc3Rlcl9DQTErMCkGCSqGSIb3DQEJ\r\n"  \
"ARYcdG9iaWFzLnNjaGxhZXBmZXJAYmx1ZXdpbi5jaDAeFw0xOTA5MDYwNjMyMjJa\r\n"  \
"Fw0zOTA5MDEwNjMyMjJaMIGtMQswCQYDVQQGEwJDSDEUMBIGA1UECAwLU3dpdHpl\r\n"  \
"cmxhbmQxDjAMBgNVBAcMBVV6d2lsMR8wHQYDVQQKDBZFbWJlZGRlZCBTZWN1cml0\r\n"  \
"eSBHbWJIMRYwFAYDVQQLDA1UZWFtIFNlY3VyaXR5MRIwEAYDVQQDDAlNYXN0ZXJf\r\n"  \
"Q0ExKzApBgkqhkiG9w0BCQEWHHRvYmlhcy5zY2hsYWVwZmVyQGJsdWV3aW4uY2gw\r\n"  \
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQJHKNXDlR5ffYAt6+ZyhvEKmEV0+T9\r\n"  \
"qtwHzPaIecxteSguSC5nTm5DRLtglTD0Xx12Ov/1UdFLeaqMAqYS/n52o2MwYTAd\r\n"  \
"BgNVHQ4EFgQUFjdDUMu1TXi3TDKyhdLmoYgBBugwHwYDVR0jBBgwFoAUFjdDUMu1\r\n"  \
"TXi3TDKyhdLmoYgBBugwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYw\r\n"  \
"CgYIKoZIzj0EAwIDSQAwRgIhALveAxcCOKBHtT9eaWoNV8gViR6J6SvVYvjX3V1m\r\n"  \
"XSumAiEAucSkRiJnPEGLtwuZsWHY02JIdWde2tRdUxbn9hYX1fw=\r\n"              \
"-----END CERTIFICATE-----\r\n"

#define CLIENT_CERTIFICATE                                             \
"-----BEGIN CERTIFICATE-----\r\n"                                      \
"MIIDDjCCArSgAwIBAgICEAIwCgYIKoZIzj0EAwIwgacxCzAJBgNVBAYTAkNIMRQw\r\n" \
"EgYDVQQIDAtTd2l0emVybGFuZDEfMB0GA1UECgwWRW1iZWRkZWQgU2VjdXJpdHkg\r\n" \
"R21iSDEWMBQGA1UECwwNVGVhbSBTZWN1cml0eTEcMBoGA1UEAwwTTWFzdGVyX0lu\r\n" \
"dGVybWVkaWF0ZTErMCkGCSqGSIb3DQEJARYcdG9iaWFzLnNjaGxhZXBmZXJAYmx1\r\n" \
"ZXdpbi5jaDAeFw0xOTA5MDYwODE1NThaFw0yMTA5MDUwODE1NThaMIGvMQswCQYD\r\n" \
"VQQGEwJDSDEUMBIGA1UECAwLU3dpdHplcmxhbmQxDjAMBgNVBAcMBVV6d2lsMR8w\r\n" \
"HQYDVQQKDBZFbWJlZGRlZCBTZWN1cml0eSBHbWJIMRYwFAYDVQQLDA1UZWFtIFNl\r\n" \
"Y3VyaXR5MRQwEgYDVQQDDAtJbkVTX1NlbnNvcjErMCkGCSqGSIb3DQEJARYcdG9i\r\n" \
"aWFzLnNjaGxhZXBmZXJAYmx1ZXdpbi5jaDBZMBMGByqGSM49AgEGCCqGSM49AwEH\r\n" \
"A0IABGhbTAi3wTGTe+qe8Zpa550ERXQONF28pX7icz6x+8xJmeT6DxMsLQnn7gu/\r\n" \
"BN3etz1x6/KAU7GmsbPkMSGjlqajgcUwgcIwCQYDVR0TBAIwADARBglghkgBhvhC\r\n" \
"AQEEBAMCBaAwMwYJYIZIAYb4QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIENsaWVu\r\n" \
"dCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU9eip0k7xmMrjERGJis39Qp7KtoMwHwYD\r\n" \
"VR0jBBgwFoAUJXJuI/jYEfCh/4gpAMv0c39JW5AwDgYDVR0PAQH/BAQDAgXgMB0G\r\n" \
"A1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAKBggqhkjOPQQDAgNIADBFAiEA\r\n" \
"vCQwhCkW24eHE4IIldDX/L3L8IHsMgOr1nr2wXJruQwCIHFQ5J8RzAoi8+uaUxSA\r\n" \
"JkL2jxr3NFz7hAH7FDmXZe9s\r\n"                                         \
"-----END CERTIFICATE-----\r\n"

#define CLIENT_PRIVATE_KEY                                             \
"-----BEGIN EC PARAMETERS-----\r\n"                                    \
"BggqhkjOPQMBBw==\r\n"                                                 \
"-----END EC PARAMETERS-----\r\n"                                      \
"-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
"MHcCAQEEIGPu40vCeKMtc/hl1IDBscdu/BYs/4iDZvjVvau+f35/oAoGCCqGSM49\r\n" \
"AwEHoUQDQgAEaFtMCLfBMZN76p7xmlrnnQRFdA40XbylfuJzPrH7zEmZ5PoPEywt\r\n" \
"CefuC78E3d63PXHr8oBTsaaxs+QxIaOWpg==\r\n"                             \
"-----END EC PRIVATE KEY-----\r\n"

static psa_status_t se050_to_psa_error(sss_status_t aReturnValue)
{
    switch(aReturnValue)
    {
        case kStatus_SSS_Success:
            return PSA_SUCCESS;
            break;
        case kStatus_SSS_Fail:
            return PSA_ERROR_GENERIC_ERROR;
            break;
        case kStatus_SSS_InvalidArgument:
            return PSA_ERROR_INVALID_ARGUMENT;
            break;
        case kStatus_SSS_ResourceBusy:
            return PSA_ERROR_CONNECTION_BUSY;
            break;
        default:
            return PSA_ERROR_HARDWARE_FAILURE;
            break;
    }
}

// static sss_session_t     sssSession;
// static SE_Connect_Ctx_t  sssConnectionData;

static bool se050Initialized = false;

static sss_rng_context_t sssRandom;
static sss_key_store_t   sssKeyStore;
static sss_key_store_t   sssClientKey;
static sss_key_store_t   sssClientCert;
static sss_key_store_t   sssCaCert;
static sss_object_t      sssObject;
static sss_digest_t      sssDigest;
static sss_asymmetric_t  sssAsymmetric;

psa_status_t se050_init(void* ctx)
{
    sss_status_t status = kStatus_SSS_Success;
//     mbedtls_platform_context* context = (mbedtls_platform_context*)ctx;
//     printf("hello from se050_init\r\n");

//     axReset_HostConfigure();
//     axReset_PowerUp();

//     status = sss_session_create(&context->sssSession, 
//                                 kType_SSS_SE_SE05x, 
//                                 0, 
//                                 kSSS_ConnectionType_Plain, 
//                                 &context->sssConnectionData);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_session_create FAILED, 0x%x\n", status);
//         goto exit;
//     }

//     status = sss_session_open(&context->sssSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, &context->sssConnectionData);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_session_open FAILED, 0x%x\n", status);
//     }

//     se050Initialized = true;

// exit:
    return (se050_to_psa_error(status));
}

psa_status_t se050_provision(void)
{
    sss_status_t status = kStatus_SSS_Success;

    // if(!se050Initialized)
    // {
    //     return PSA_ERROR_BAD_STATE;
    // }

    /* Check whether the SE050 is already provisioned */
    // status = sss_key_store_context_init(&sssKeyStore, &sssSession);
    // if(status != kStatus_SSS_Success)
    // {
    //     printf("sss_key_store_context_init FAILED, 0x%x\n", status);
    //     goto exit;
    // }

    // status = sss_key_store_allocate(&sssKeyStore, slot);
    // if(status != kStatus_SSS_Success)
    // {
    //     printf("sss_key_store_allocate FAILED, 0x%x\n", status);
    //     goto exit;
    // }

    // status = sss_key_object_init(&sssObject, &sssKeyStore);
    // if(status != kStatus_SSS_Success)
    // {   
    //     printf("sss_key_object_init FAILED, 0x%x\n", status);
    //     goto exit;
    // }

    // printf("sss_key_object_init SUCCESS, key size %d\r\n", PSA_ECC_CURVE_BITS(PSA_ECC_CURVE_SECP256R1));

    // /* Map PSA crypto parameters to sss parameters */

    // status = sss_key_object_allocate_handle(&sssObject, 
    //                                         slot, 
    //                                         kSSS_KeyPart_Pair,
    //                                         kSSS_CipherType_EC_NIST_P,
    //                                         PSA_ECC_CURVE_BITS(PSA_ECC_CURVE_SECP256R1),
    //                                         kKeyObject_Mode_Persistent);
    // if(status != kStatus_SSS_Success)
    // {   
    //     printf("sss_key_object_allocate_handle FAILED, 0x%x\n", status);
    // }
    
    return (se050_to_psa_error(status));
}

/******************************************************************************
 * PSA secure element support functions, not yet ready to be used in the MT
 * application. 
 ******************************************************************************/

/* Init function */

// static psa_status_t se050_init(psa_drv_se_context_t *aDrvContext,
//                                void *aPersistentData,
//                                psa_key_lifetime_t aLifetime)
// {
//     sss_status_t status = kStatus_SSS_Success;

//     printf("hello from se050_init\r\n");

//     axReset_HostConfigure();
//     axReset_PowerUp();

//     status = sss_session_create(&sssSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, &sssConnectionData);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_session_create FAILED, 0x%x\n", status);
//         goto exit;
//     }

//     status = sss_session_open(&sssSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, &sssConnectionData);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_session_open FAILED, 0x%x\n", status);
//     }

//     se050Initialized = true;

// exit:
//     return (se050_to_psa_error(status));
// }

/* Key management functions */

// static psa_status_t se050_allocate_key(psa_drv_se_context_t *aDrvContext,
//                                        void *aPersistentData,
//                                        const psa_key_attributes_t *aAttributes,
//                                        psa_key_creation_method_t aMethod,
//                                        psa_key_slot_number_t *aKeySlot)
// {
//     sss_status_t status = kStatus_SSS_Success;
//     uint32_t slot = *aKeySlot + 1;

//     status = sss_key_store_context_init(&sssKeyStore, &sssSession);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_context_init FAILED, 0x%x\n", status);
//         goto exit;
//     }

//     status = sss_key_store_allocate(&sssKeyStore, slot);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_allocate FAILED, 0x%x\n", status);
//         goto exit;
//     }

//     status = sss_key_object_init(&sssObject, &sssKeyStore);
//     if(status != kStatus_SSS_Success)
//     {   
//         printf("sss_key_object_init FAILED, 0x%x\n", status);
//         goto exit;
//     }

//     printf("sss_key_object_init SUCCESS, key size %d\r\n", PSA_ECC_CURVE_BITS(PSA_ECC_CURVE_SECP256R1));

//     /* Map PSA crypto parameters to sss parameters */

//     status = sss_key_object_allocate_handle(&sssObject, 
//                                             slot, 
//                                             kSSS_KeyPart_Pair,
//                                             kSSS_CipherType_EC_NIST_P,
//                                             PSA_ECC_CURVE_BITS(PSA_ECC_CURVE_SECP256R1),
//                                             kKeyObject_Mode_Persistent);
//     if(status != kStatus_SSS_Success)
//     {   
//         printf("sss_key_object_allocate_handle FAILED, 0x%x\n", status);
//     }

//     printf("sss_key_object_allocate_handle SUCCESS\r\n");

// exit:
//     return (se050_to_psa_error(status));
// }

// static psa_status_t se050_validate_slot_number(psa_drv_se_context_t *aDrvContext,
//                                                void *aPersistentData,
//                                                const psa_key_attributes_t *aAttributes,
//                                                psa_key_creation_method_t aMethod,
//                                                psa_key_slot_number_t aKeySlot)
// {
//     printf("hello from se050_validate_slot_number\n");



//     return PSA_SUCCESS;
// }

// static psa_status_t se050_import_key(psa_drv_se_context_t *aDrvContext,
//                                      psa_key_slot_number_t aKeySlot,
//                                      const psa_key_attributes_t *aAttributes,
//                                      const uint8_t *aKeyBuf,
//                                      size_t aKeyBufLen,
//                                      size_t *aBits)
// {
//     printf("hello from se050_import_key\n");
//     return PSA_SUCCESS;
// }

// static psa_status_t se050_generate_key(psa_drv_se_context_t *aDrvContext,
//                                        psa_key_slot_number_t aKeySlot,
//                                        const psa_key_attributes_t *aAttributes,
//                                        uint8_t *aPubKeyBuf, 
//                                        size_t aPubKeyBufLen, 
//                                        size_t *aPublicKeyLen)
// {
//     printf("hello from se050_generate_key\r\n");

//     sss_status_t status = kStatus_SSS_Success;

// exit:
//     return (se050_to_psa_error(status));
// }

// static psa_status_t se050_export_public_key(psa_drv_se_context_t *aDrvContext,
//                                             psa_key_slot_number_t aKeySlot,
//                                             uint8_t *aPubKeyBuf,
//                                             size_t aPubKeyBufLen,
//                                             size_t *aPublicKeyLen)
// {
//     printf("hello from se050_export_public_key\n");
//     return PSA_ERROR_NOT_SUPPORTED;
// }

// static psa_drv_se_key_management_t se050_key_management = 
// {
//     .p_allocate = se050_allocate_key,
//     .p_validate_slot_number = se050_validate_slot_number,
//     .p_import = se050_import_key,
//     .p_generate = se050_generate_key,
//     .p_destroy = 0,
//     .p_export = 0,
//     .p_export_public = se050_export_public_key,
// };

// /* Asymmetric crypto functions */

// static psa_status_t se050_asymmetric_sign(psa_drv_se_context_t *aDrvContext,
//                                           psa_key_slot_number_t aKeySlot,
//                                           psa_algorithm_t aAlgorithm,
//                                           const uint8_t *aData,
//                                           size_t aDataLen,
//                                           uint8_t *aSignBuf,
//                                           size_t aSignBufLen,
//                                           size_t *aSignatureLen)
// {
//     printf("hello from se050_asymmetric_sign\n");
//     return PSA_ERROR_NOT_SUPPORTED;
// }

// static psa_status_t se050_asymmetric_verify(psa_drv_se_context_t *aDrvContext,
//                                             psa_key_slot_number_t aKeySlot,
//                                             psa_algorithm_t aAlgorithm,
//                                             const uint8_t *aData,
//                                             size_t aDataLen,
//                                             const uint8_t *aSignature,
//                                             size_t aSignatureLen)
// {
//     printf("hello from se050_asymmetric_verify\n");
//     return PSA_ERROR_NOT_SUPPORTED;
// }

// static psa_status_t se050_asymmetric_encrypt(psa_drv_se_context_t *aDrvContext,
//                                              psa_key_slot_number_t aKeySlot,
//                                              psa_algorithm_t aAlgorithm,
//                                              const uint8_t *aData,
//                                              size_t aDataLen,
//                                              const uint8_t *aSalt,
//                                              size_t aSaltLen,
//                                              uint8_t *aOutputBuf,
//                                              size_t aOutputBufLen,
//                                              size_t *aOutputLen)
// {
//     printf("hello from se050_asymmetric_encrypt\n");
//     return PSA_ERROR_NOT_SUPPORTED;
// }

// static psa_status_t se050_asymmetric_decrypt(psa_drv_se_context_t *aDrvContext,
//                                              psa_key_slot_number_t aKeySlot,
//                                              psa_algorithm_t aAlgorithm,
//                                              const uint8_t *aData,
//                                              size_t aDataLength,
//                                              const uint8_t *aSalt,
//                                              size_t aSaltLen,
//                                              uint8_t *aOutputBuf,
//                                              size_t aOutputBufLen,
//                                              size_t *aOutputLen)
// {
//     printf("hello from se050_asymmetric_decrypt\n");
//     return PSA_ERROR_NOT_SUPPORTED;
// }

// static psa_drv_se_asymmetric_t se050_asymmetric = 
// {
//     .p_sign = se050_asymmetric_sign,
//     .p_verify = se050_asymmetric_verify,
//     .p_encrypt = se050_asymmetric_encrypt,
//     .p_decrypt = se050_asymmetric_decrypt,
// };

psa_drv_se_t se050_drv_info = {
    //.p_init = se050_init,
    .key_management = NULL, //&se050_key_management,
    .mac = NULL,
    .cipher = NULL,
    .asymmetric = NULL,     //&se050_asymmetric,
    .aead = NULL,
    .derivation = NULL,
    .hal_version = PSA_DRV_SE_HAL_VERSION
};