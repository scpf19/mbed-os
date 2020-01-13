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
 * \file        platform_alt.c
 *
 * \description Module implements a set of cryptographic operations using the 
 *              SE050 and provides these function for the SE driver in the TF-M.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        17.12.2019
 *
 *****************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(FLOW_VERBOSE) && FLOW_VERBOSE == 1
#include "sm_printf.h"
#include "sm_types.h"
#endif /* FLOW_VERBOSE */

#include "mbedtls/platform.h"

// #if defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT) && SSS_HAVE_ALT_SSS

// static int se050Provision(mbedtls_platform_context *ctx)
// {
//     sss_status_t status = kStatus_SSS_Success;
//     /* TODO_scpf
//      * 1. check if already provisioned */
//     /* 2. Provision */

//     /* Slot for the private key of the client certificate */
//     status = sss_key_store_context_init(&ctx->sssClientKey, &ctx->sssSession);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_context_init FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_store_allocate(&ctx->sssClientKey, 1);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_allocate FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     /* freeze key once it works */
//     //sss_key_store_freeze_key

//     /* Slot for the client certificate */
//     status = sss_key_store_context_init(&ctx->sssClientCert, &ctx->sssSession);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_context_init FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_store_allocate(&ctx->sssClientCert, 2);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_allocate FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     /* Slot for the CA certificate */
//     status = sss_key_store_context_init(&ctx->sssCaCert, &ctx->sssSession);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_context_init FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_store_allocate(&ctx->sssCaCert, 3);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_allocate FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     /* Slot for the ephemeral key */
//     status = sss_key_store_context_init(&ctx->sssEphemeral, &ctx->sssSession);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_context_init FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_store_allocate(&ctx->sssEphemeral, 4);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_allocate FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_object_init(&ctx->sssEphemeralObject, &ctx->sssEphemeral);
//     if(status != kStatus_SSS_Success)
//     {   
//         printf("sss_key_object_init FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_object_allocate_handle(&ctx->sssEphemeralObject, 
//                                             4, 
//                                             kSSS_KeyPart_Pair,
//                                             kSSS_CipherType_EC_NIST_P,
//                                             256,
//                                             kKeyObject_Mode_Persistent);
//     if(status != kStatus_SSS_Success)
//     {   
//         printf("sss_key_object_allocate_handle FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     /* Slot for the session key */
//     status = sss_key_store_context_init(&ctx->sssSessionKey, &ctx->sssSession);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_context_init FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     status = sss_key_store_allocate(&ctx->sssSessionKey, 5);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_key_store_allocate FAILED, 0x%x\n", status);
//         return -1; //TODO_scpf find hardware error 
//     }

//     return 0;
// }

// int mbedtls_platform_setup(mbedtls_platform_context *ctx)
// {
//     sss_status_t status = kStatus_SSS_Success;

//     status = sss_session_create(&ctx->sssSession, 
//                                 kType_SSS_SE_SE05x, 
//                                 0, 
//                                 kSSS_ConnectionType_Plain, 
//                                 &ctx->sssConnectionData);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_session_create FAILED, 0x%x\n", status);
//         return -1;
//     }

//     status = sss_session_open(&ctx->sssSession, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, &ctx->sssConnectionData);
//     if(status != kStatus_SSS_Success)
//     {
//         printf("sss_session_open FAILED, 0x%x\n", status);
//     }

//     if(se050Provision(ctx) < 0)
//     {
//         printf("Provisioning FAILED!\n");
//     }

//     return( 0 );
// }

// /*
//  * Placeholder platform teardown that does nothing by default
//  */
// void mbedtls_platform_teardown( mbedtls_platform_context *ctx )
// {
//     sss_session_close(&ctx->sssSession);
// }

// #endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT && SSS_HAVE_ALT_SSS */
