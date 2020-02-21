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
 * \file        tls_alt_sss.c
 *
 * \description Module implements all mbedTLS hooks required to execute a TLS
 *              handshake with the support of the SE050.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        18.12.2019
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>

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
#include "mbedtls/ecdh.h"
#include "mbedtls/version.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"

#include "mbed_stats.h"
#include "mbed_mem_trace.h"

#include "ax_reset.h"
#include "fsl_sss_api.h"
#include "nxScp03_Types.h"
#include <fsl_sss_util_asn1_der.h>
#include <nxLog_sss.h>
#include "ex_sss_boot.h"

#include "psa/crypto_sizes.h"
#include "psa_se050.h"

#define CLIENT_KEY_SLOT                     0xAFFE
#define CLIENT_CERTIFICATE_SLOT             0xBEEF
#define CA_CERTIFICATE_SLOT                 0xCAFE
#define PW_SLOT                             0xDEAD
#define EPHEMERAL_KEY_SLOT                  4
#define SESSION_KEY_SLOT                    15
#define OTHER_PARTY_KEY_SLOT                6
#define MASTER_SECRET_KEY_SLOT              17
#define TMP_KEY_SLOT                        8

#define SIGNATURE_MAX_LENGTH                72

const uint8_t caCert[] = 
{
    0x30, 0x82, 0x02, 0xac, 0x30, 0x82, 0x02, 0x52, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x10,
    0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x81, 0xad,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x48, 0x31, 0x14, 0x30,
    0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x53, 0x77, 0x69, 0x74, 0x7a, 0x65, 0x72, 0x6c,
    0x61, 0x6e, 0x64, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x05, 0x55, 0x7a,
    0x77, 0x69, 0x6c, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x16, 0x45, 0x6d,
    0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20,
    0x47, 0x6d, 0x62, 0x48, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x54,
    0x65, 0x61, 0x6d, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x31, 0x12, 0x30, 0x10,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x43, 0x41,
    0x31, 0x2b, 0x30, 0x29, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
    0x1c, 0x74, 0x6f, 0x62, 0x69, 0x61, 0x73, 0x2e, 0x73, 0x63, 0x68, 0x6c, 0x61, 0x65, 0x70, 0x66,
    0x65, 0x72, 0x40, 0x62, 0x6c, 0x75, 0x65, 0x77, 0x69, 0x6e, 0x2e, 0x63, 0x68, 0x30, 0x1e, 0x17,
    0x0d, 0x31, 0x39, 0x30, 0x39, 0x30, 0x36, 0x30, 0x36, 0x33, 0x38, 0x35, 0x33, 0x5a, 0x17, 0x0d,
    0x32, 0x39, 0x30, 0x39, 0x30, 0x33, 0x30, 0x36, 0x33, 0x38, 0x35, 0x33, 0x5a, 0x30, 0x81, 0xa7,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x48, 0x31, 0x14, 0x30,
    0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x53, 0x77, 0x69, 0x74, 0x7a, 0x65, 0x72, 0x6c,
    0x61, 0x6e, 0x64, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x16, 0x45, 0x6d,
    0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20,
    0x47, 0x6d, 0x62, 0x48, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x54,
    0x65, 0x61, 0x6d, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x31, 0x1c, 0x30, 0x1a,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x49, 0x6e,
    0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x1c, 0x74, 0x6f, 0x62, 0x69, 0x61,
    0x73, 0x2e, 0x73, 0x63, 0x68, 0x6c, 0x61, 0x65, 0x70, 0x66, 0x65, 0x72, 0x40, 0x62, 0x6c, 0x75,
    0x65, 0x77, 0x69, 0x6e, 0x2e, 0x63, 0x68, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0xe4, 0xce, 0x29, 0x45, 0x86, 0xd4, 0xba, 0x11, 0x5b, 0x34, 0x01, 0x2f, 0x79, 0x0a,
    0xdf, 0x8d, 0x29, 0x0b, 0xe9, 0xab, 0x79, 0x63, 0x55, 0xb9, 0xe5, 0xb1, 0x3a, 0x5f, 0xa9, 0x9f,
    0x42, 0xa2, 0xa7, 0xaa, 0xf8, 0x13, 0x90, 0xe2, 0xc6, 0x4e, 0x2e, 0xd8, 0x6e, 0xb6, 0x56, 0x1c,
    0x3b, 0xc7, 0x2e, 0x6d, 0x1e, 0x96, 0xcd, 0x4b, 0x88, 0x35, 0x94, 0x31, 0xc9, 0xa3, 0xc1, 0xff,
    0xbc, 0xab, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
    0x14, 0x25, 0x72, 0x6e, 0x23, 0xf8, 0xd8, 0x11, 0xf0, 0xa1, 0xff, 0x88, 0x29, 0x00, 0xcb, 0xf4,
    0x73, 0x7f, 0x49, 0x5b, 0x90, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0x16, 0x37, 0x43, 0x50, 0xcb, 0xb5, 0x4d, 0x78, 0xb7, 0x4c, 0x32, 0xb2, 0x85, 0xd2,
    0xe6, 0xa1, 0x88, 0x01, 0x06, 0xe8, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x85, 0xa3,
    0xb1, 0x55, 0xdf, 0x00, 0x12, 0xea, 0xf0, 0xf0, 0xf0, 0x05, 0x7c, 0x6b, 0x96, 0xf1, 0x1d, 0x57,
    0x43, 0x38, 0xf6, 0xc1, 0x62, 0xe1, 0xf3, 0x88, 0xdf, 0x39, 0x51, 0xcb, 0xad, 0x9e, 0x02, 0x20,
    0x1c, 0xf0, 0xee, 0xfb, 0x69, 0x39, 0x93, 0x7c, 0x24, 0x70, 0x06, 0xf3, 0x9f, 0x9a, 0x34, 0x19,
    0x50, 0x43, 0xfc, 0x4d, 0x61, 0x23, 0xf7, 0x8e, 0x96, 0x64, 0x02, 0x90, 0xad, 0xd9, 0xd9, 0xc6,
};

const uint8_t clientCert[] =
{
    0x30, 0x82, 0x03, 0x0e, 0x30, 0x82, 0x02, 0xb4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x10, 
    0x02, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x81, 0xa7, 
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x48, 0x31, 0x14, 0x30, 
    0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x53, 0x77, 0x69, 0x74, 0x7a, 0x65, 0x72, 0x6c, 
    0x61, 0x6e, 0x64, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x16, 0x45, 0x6d, 
    0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 
    0x47, 0x6d, 0x62, 0x48, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x54, 
    0x65, 0x61, 0x6d, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x31, 0x1c, 0x30, 0x1a, 
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x49, 0x6e, 
    0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x09, 
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x1c, 0x74, 0x6f, 0x62, 0x69, 0x61, 
    0x73, 0x2e, 0x73, 0x63, 0x68, 0x6c, 0x61, 0x65, 0x70, 0x66, 0x65, 0x72, 0x40, 0x62, 0x6c, 0x75, 
    0x65, 0x77, 0x69, 0x6e, 0x2e, 0x63, 0x68, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x39, 0x30, 
    0x36, 0x30, 0x38, 0x31, 0x35, 0x35, 0x38, 0x5a, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x39, 0x30, 0x35, 
    0x30, 0x38, 0x31, 0x35, 0x35, 0x38, 0x5a, 0x30, 0x81, 0xaf, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 
    0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x48, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 
    0x0c, 0x0b, 0x53, 0x77, 0x69, 0x74, 0x7a, 0x65, 0x72, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x0e, 0x30, 
    0x0c, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x05, 0x55, 0x7a, 0x77, 0x69, 0x6c, 0x31, 0x1f, 0x30, 
    0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x16, 0x45, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 
    0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x47, 0x6d, 0x62, 0x48, 0x31, 0x16, 
    0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x54, 0x65, 0x61, 0x6d, 0x20, 0x53, 0x65, 
    0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 
    0x0b, 0x49, 0x6e, 0x45, 0x53, 0x5f, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x31, 0x2b, 0x30, 0x29, 
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x1c, 0x74, 0x6f, 0x62, 
    0x69, 0x61, 0x73, 0x2e, 0x73, 0x63, 0x68, 0x6c, 0x61, 0x65, 0x70, 0x66, 0x65, 0x72, 0x40, 0x62, 
    0x6c, 0x75, 0x65, 0x77, 0x69, 0x6e, 0x2e, 0x63, 0x68, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 
    0x03, 0x42, 0x00, 0x04, 0x68, 0x5b, 0x4c, 0x08, 0xb7, 0xc1, 0x31, 0x93, 0x7b, 0xea, 0x9e, 0xf1, 
    0x9a, 0x5a, 0xe7, 0x9d, 0x04, 0x45, 0x74, 0x0e, 0x34, 0x5d, 0xbc, 0xa5, 0x7e, 0xe2, 0x73, 0x3e, 
    0xb1, 0xfb, 0xcc, 0x49, 0x99, 0xe4, 0xfa, 0x0f, 0x13, 0x2c, 0x2d, 0x09, 0xe7, 0xee, 0x0b, 0xbf, 
    0x04, 0xdd, 0xde, 0xb7, 0x3d, 0x71, 0xeb, 0xf2, 0x80, 0x53, 0xb1, 0xa6, 0xb1, 0xb3, 0xe4, 0x31, 
    0x21, 0xa3, 0x96, 0xa6, 0xa3, 0x81, 0xc5, 0x30, 0x81, 0xc2, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 
    0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 
    0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x33, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 
    0x86, 0xf8, 0x42, 0x01, 0x0d, 0x04, 0x26, 0x16, 0x24, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x4c, 
    0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 
    0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x1d, 0x06, 
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xf5, 0xe8, 0xa9, 0xd2, 0x4e, 0xf1, 0x98, 0xca, 
    0xe3, 0x11, 0x11, 0x89, 0x8a, 0xcd, 0xfd, 0x42, 0x9e, 0xca, 0xb6, 0x83, 0x30, 0x1f, 0x06, 0x03, 
    0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x25, 0x72, 0x6e, 0x23, 0xf8, 0xd8, 0x11, 
    0xf0, 0xa1, 0xff, 0x88, 0x29, 0x00, 0xcb, 0xf4, 0x73, 0x7f, 0x49, 0x5b, 0x90, 0x30, 0x0e, 0x06, 
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xe0, 0x30, 0x1d, 0x06, 
    0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 
    0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x30, 0x0a, 0x06, 0x08, 
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 
    0xbc, 0x24, 0x30, 0x84, 0x29, 0x16, 0xdb, 0x87, 0x87, 0x13, 0x82, 0x08, 0x95, 0xd0, 0xd7, 0xfc, 
    0xbd, 0xcb, 0xf0, 0x81, 0xec, 0x32, 0x03, 0xab, 0xd6, 0x7a, 0xf6, 0xc1, 0x72, 0x6b, 0xb9, 0x0c, 
    0x02, 0x20, 0x71, 0x50, 0xe4, 0x9f, 0x11, 0xcc, 0x0a, 0x22, 0xf3, 0xeb, 0x9a, 0x53, 0x14, 0x80, 
    0x26, 0x42, 0xf6, 0x8f, 0x1a, 0xf7, 0x34, 0x5c, 0xfb, 0x84, 0x01, 0xfb, 0x14, 0x39, 0x97, 0x65, 
    0xef, 0x6c
};

const uint8_t clientKey[] =
{
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x63, 0xee, 0xe3, 0x4b, 0xc2, 0x78, 0xa3, 0x2d, 0x73,
    0xf8, 0x65, 0xd4, 0x80, 0xc1, 0xb1, 0xc7, 0x6e, 0xfc, 0x16, 0x2c, 0xff, 0x88, 0x83, 0x66, 0xf8,
    0xd5, 0xbd, 0xab, 0xbe, 0x7f, 0x7e, 0x7f, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x68, 0x5b, 0x4c, 0x08, 0xb7, 0xc1, 0x31,
    0x93, 0x7b, 0xea, 0x9e, 0xf1, 0x9a, 0x5a, 0xe7, 0x9d, 0x04, 0x45, 0x74, 0x0e, 0x34, 0x5d, 0xbc,
    0xa5, 0x7e, 0xe2, 0x73, 0x3e, 0xb1, 0xfb, 0xcc, 0x49, 0x99, 0xe4, 0xfa, 0x0f, 0x13, 0x2c, 0x2d,
    0x09, 0xe7, 0xee, 0x0b, 0xbf, 0x04, 0xdd, 0xde, 0xb7, 0x3d, 0x71, 0xeb, 0xf2, 0x80, 0x53, 0xb1,
    0xa6, 0xb1, 0xb3, 0xe4, 0x31, 0x21, 0xa3, 0x96, 0xa6
};

static uint8_t            provisionState = 0;

/* Platform wide known sssSession */
sss_session_t             sssSessionSE;


static sss_session_t      sssHostSession;
static SE_Connect_Ctx_t   sssConnectionDataHost;
static sss_key_store_t    sssHostKeyStore;
static ex_SE05x_authCtx_t sssHostAuthCtx;

static SE_Connect_Ctx_t   sssConnectionDataSE;

static sss_key_store_t    sssCertKey;
static sss_object_t       sssCertKeyObject;
static sss_key_store_t    sssCertSlot;
static sss_object_t       sssCertObject;
static sss_key_store_t    sssCaSlot;
static sss_object_t       sssCaObject;
static sss_key_store_t    sssPrivateKey;
static sss_object_t       sssPrivateObject;
static sss_key_store_t    sssEphemeralKey;
static sss_object_t       sssEphemeralObject;
static sss_key_store_t    sssSessionKey;
static sss_object_t       sssSessionObject;
static sss_key_store_t    sssMasterSecretKey;
static sss_object_t       sssMasterSecretObject;

static int get_header_and_bit_Length(int groupid, int *headerLen, int *bitLen)
{
    switch (groupid) {
    case MBEDTLS_ECP_DP_SECP192R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp192_header_len;
        if (bitLen != NULL)
            *bitLen = 192;
        break;
    case MBEDTLS_ECP_DP_SECP224R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp224_header_len;
        if (bitLen != NULL)
            *bitLen = 224;
        break;
    case MBEDTLS_ECP_DP_SECP256R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp256_header_len;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp384_header_len;
        if (bitLen != NULL)
            *bitLen = 384;
        break;
    case MBEDTLS_ECP_DP_SECP521R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_nistp521_header_len;
        if (bitLen != NULL)
            *bitLen = 521;
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_bp256_header_len;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    case MBEDTLS_ECP_DP_BP384R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_bp384_header_len;
        if (bitLen != NULL)
            *bitLen = 384;
        break;
    case MBEDTLS_ECP_DP_BP512R1:
        if (headerLen != NULL)
            *headerLen = der_ecc_bp512_header_len;
        if (bitLen != NULL)
            *bitLen = 512;
        break;
    case MBEDTLS_ECP_DP_SECP192K1:
        if (headerLen != NULL)
            *headerLen = der_ecc_192k_header_len;
        if (bitLen != NULL)
            *bitLen = 192;
        break;
    case MBEDTLS_ECP_DP_SECP224K1:
        if (headerLen != NULL)
            *headerLen = der_ecc_224k_header_len;
        if (bitLen != NULL)
            *bitLen = 224;
        break;
    case MBEDTLS_ECP_DP_SECP256K1:
        if (headerLen != NULL)
            *headerLen = der_ecc_256k_header_len;
        if (bitLen != NULL)
            *bitLen = 256;
        break;
    default:
        LOG_E("get_header_and_bit_Length: Group id not supported");
        return 1;
    }

    return 0;
}

static int convertPublicKey(mbedtls_ecp_group *grp,
                            const mbedtls_ecp_point *Q,
                            sss_cipher_type_t* pubKeyType,
                            uint8_t* pubKey, 
                            size_t* pubKeyLen,
                            size_t* pubKeyBitLen)
{
    int headerLen = 0;

    if(get_header_and_bit_Length(grp->id, &headerLen, pubKeyBitLen)) 
    {
        printf("Curve not supported by the SE050, 0x%x\r\n",grp->id);
        return 1;
    }

    if(0 == mbedtls_ecp_point_write_binary(grp,
                                           Q,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           pubKeyLen,
                                           (pubKey + headerLen),
                                           *pubKeyLen)) 
    {
        switch (grp->id) {
        case MBEDTLS_ECP_DP_SECP192R1:
            memcpy(pubKey,
                gecc_der_header_nist192,
                der_ecc_nistp192_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_nistp192_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_P;
            break;
        case MBEDTLS_ECP_DP_SECP224R1:
            memcpy(pubKey,
                gecc_der_header_nist224,
                der_ecc_nistp224_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_nistp224_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_P;
            break;
        case MBEDTLS_ECP_DP_SECP256R1:
            memcpy(pubKey,
                gecc_der_header_nist256,
                der_ecc_nistp256_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_nistp256_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_P;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            memcpy(pubKey,
                gecc_der_header_nist384,
                der_ecc_nistp384_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_nistp384_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_P;
            break;
        case MBEDTLS_ECP_DP_SECP521R1:
            memcpy(pubKey,
                gecc_der_header_nist521,
                der_ecc_nistp521_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_nistp521_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_P;
            break;
        case MBEDTLS_ECP_DP_BP256R1:
            memcpy(pubKey,
                gecc_der_header_bp256,
                der_ecc_bp256_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_bp256_header_len;
            *pubKeyType = kSSS_CipherType_EC_BRAINPOOL;
            break;
        case MBEDTLS_ECP_DP_BP384R1:
            memcpy(pubKey,
                gecc_der_header_bp384,
                der_ecc_bp384_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_bp384_header_len;
            *pubKeyType = kSSS_CipherType_EC_BRAINPOOL;
            break;
        case MBEDTLS_ECP_DP_BP512R1:
            memcpy(pubKey,
                gecc_der_header_bp512,
                der_ecc_bp512_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_bp512_header_len;
            *pubKeyType = kSSS_CipherType_EC_BRAINPOOL;
            break;
        case MBEDTLS_ECP_DP_SECP192K1:
            memcpy(pubKey,
                gecc_der_header_192k,
                der_ecc_192k_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_192k_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_K;
            break;
        case MBEDTLS_ECP_DP_SECP224K1:
            memcpy(pubKey,
                gecc_der_header_224k,
                der_ecc_224k_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_224k_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_K;
            break;
        case MBEDTLS_ECP_DP_SECP256K1:
            memcpy(pubKey,
                gecc_der_header_256k,
                der_ecc_256k_header_len);
            *pubKeyLen = *pubKeyLen + der_ecc_256k_header_len;
            *pubKeyType = kSSS_CipherType_EC_NIST_K;
            break;
        default:
            printf("Curve not supported by the KEY CONVERSION, 0x%x\r\n", grp->id);
            return 1;
        }
    }

    return 0;
}

static int parseMpiToAsn1(mbedtls_mpi* r, mbedtls_mpi* s, uint8_t* signature, size_t* signLen)
{
    uint8_t  tmp[SIGNATURE_MAX_LENGTH];
    uint8_t  tmpLen = 0;
    uint8_t  lsignR = 0, lsignS = 0;

    if(signLen < SIGNATURE_MAX_LENGTH)
    {
        return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }

    lsignR = mbedtls_mpi_size(r);
    lsignS = mbedtls_mpi_size(s);

    tmp[0] = 0x30; /* DER_PREFIX */
    tmp[2] = 0x02; /* Marks the start of the r component */

    /* Check whether the r component is negatie or not */
    if(lsignR == 32)
    {
        /* Padding */
        tmp[3] = lsignR + 1;
        tmp[4] = 0x00;
        tmpLen = 5;
    }else
    {
        tmp[3] = lsignR;
        tmpLen = 4;
    }

    if(mbedtls_mpi_write_binary(r, &tmp[tmpLen], lsignR))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    tmpLen += lsignR;
    tmp[tmpLen] = 0x02; /* Marks the start of the s component */
    tmpLen += 1;

    /* Check whether the s component is negatie or not */
    if(lsignS == 32)
    {   
        /* Padding */
        tmp[tmpLen] = lsignS + 1;
        tmpLen += 1;
        tmp[tmpLen] = 0x00;
        tmpLen += 1;
    }else
    {
        tmp[tmpLen] = lsignS;
        tmpLen += 1;
    }

    if(mbedtls_mpi_write_binary(s, &tmp[tmpLen], lsignS))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    tmpLen += lsignS;
    /* Length without DER_PREFIX and the remaining_length byte */
    tmp[1] = (tmpLen - 2); 

    if(tmpLen <= SIGNATURE_MAX_LENGTH)
    {
        memcpy(signature, tmp, tmpLen);
        *signLen = tmpLen;

        return 0;
    }

    return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
}

static int parseAsn1ToMpi(mbedtls_mpi* r, mbedtls_mpi* s, uint8_t* signature, size_t* signLen)
{
    int     ret     = 0;
    uint8_t lengthR = 0;
    uint8_t lengthS = 0;

    /* Get the length of the r component */
    lengthR = signature[3];

    if(lengthR == 32)
    {   /* r is positive, no 0 padding*/
        ret = mbedtls_mpi_read_binary(r, &signature[4], lengthR);
    }else 
    {   /* r is negative, not include 0 padding */
        ret = mbedtls_mpi_read_binary(r, &signature[5], lengthR-1);
    }

    /* Get the length of the s component */
    lengthS = signature[5 + lengthR];

    if(lengthS == 32)
    {   /* s is positive, no 0 padding*/
        ret = mbedtls_mpi_read_binary(s, &signature[6 + lengthR], lengthS);
    }else
    {   /* s is negative, not include 0 padding */
        ret = mbedtls_mpi_read_binary(s, &signature[7 + lengthR], lengthS-1);
    }

    return ret;
}

static int defineEcdsaHashAlgorithm(sss_algorithm_t* aHashAlgorithm, uint8_t aHashLen)
{
    /* Define hash algorithm to be used for verification */
    switch (aHashLen)
    {
    case 28:
        *aHashAlgorithm = kAlgorithm_SSS_ECDSA_SHA224;
        break;

    case 32:
        *aHashAlgorithm = kAlgorithm_SSS_ECDSA_SHA256;
        break;

    case 48:
        *aHashAlgorithm = kAlgorithm_SSS_ECDSA_SHA384;
        break;

    case 64:
        *aHashAlgorithm = kAlgorithm_SSS_ECDSA_SHA512;
        break;
    
    default:
        printf("Unsupported Hash algorithms requested\r\n");
        aHashAlgorithm = NULL;
        break;
    }
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_SIGN_ALT) && SSS_HAVE_ALT_SSS

int mbedtls_ecdsa_can_do( mbedtls_ecp_group_id gid )
{
    size_t headerSize = 0;
    size_t bitlength = 0;

    if(get_header_and_bit_Length(gid, headerSize, bitlength))
    {
        /* Return 0 if the SE does not support the curve*/
        return 0;
    }else
    {
        /* Return 1 if the SE does support the curve*/
        return 1;
    }
}

int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                        const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    sss_status_t      status = kStatus_SSS_Success;
    sss_asymmetric_t  sssAsymmetricCtx;
    sss_key_store_t   sssKeyStore;
    sss_object_t      sssKeyObject;
    sss_algorithm_t   sssEcdsaHashAlgorithm;

    int ret = 0;
    uint8_t signature[PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE] = {0};
    size_t signatureLen = sizeof(signature);

    defineEcdsaHashAlgorithm(&sssEcdsaHashAlgorithm, blen);
    
    if(sssEcdsaHashAlgorithm == NULL)
    {
        printf("NO ECDSA hash algorithm found\r\n");
        return -1;
    }

    status = sss_key_store_context_init(&sssKeyStore, &sssSessionSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init FAILED, 0x%x\n", status);
        return -1;
    }

    status = sss_key_store_load(&sssKeyStore);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init FAILED, 0x%x\n", status);
        return -1;
    }

    status = sss_key_object_init(&sssKeyObject, &sssKeyStore);
    if(status != kStatus_SSS_Success) 
    {
        printf("sss_key_object_init for CA cert FAILED, 0x%x\n", status);
        return -1;
    }

    status = sss_key_object_get_handle(&sssKeyObject, CLIENT_KEY_SLOT);
    if(status != kStatus_SSS_Success) 
    {
        printf("sss_key_object_init for CA cert FAILED, 0x%x\n", status);
        return -1;
    }

    status = sss_asymmetric_context_init(&sssAsymmetricCtx,
                                         &sssSessionSE,
                                         &sssKeyObject,
                                         sssEcdsaHashAlgorithm,
                                         kMode_SSS_Sign);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_asymmetric_context_init FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_asymmetric_sign_digest(&sssAsymmetricCtx,
                                        buf,
                                        blen,
                                        signature,
                                        &signatureLen);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_asymmetric_sign_digest FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    if(parseAsn1ToMpi(r, s, &signature, &signatureLen) != 0)
    {
        printf("Signature convertion FAILED\r\n");
        ret = -1;
        goto cleanUp;
    }

cleanUp:
    sss_asymmetric_context_free(&sssAsymmetricCtx);
    sss_key_store_context_free(&sssKeyStore);
    sss_key_object_free(&sssKeyObject);

    return ret; 
}

#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_SIGN_ALT) && SSS_HAVE_ALT_SSS */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_VERIFY_ALT) && SSS_HAVE_ALT_SSS

int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s)
{
    sss_status_t      status = kStatus_SSS_Success;
    sss_cipher_type_t pubKeyType;
    sss_key_store_t   sssPubKeySlot;
    sss_object_t      sssPubKeyObject;
    sss_asymmetric_t  sssAsymmetricCtx;
    sss_algorithm_t   sssEcdsaHashAlgorithm;

    int      ret = 0;
    uint8_t  pubKeyBuffer[256] = {0};
    uint8_t  signature[SIGNATURE_MAX_LENGTH];
    size_t   signatureLen = SIGNATURE_MAX_LENGTH;
    size_t   pubKeyBufferLen = sizeof(pubKeyBuffer);
    size_t   pubKeyBitLen = 0;

    if(convertPublicKey(grp, 
                        Q,
                        &pubKeyType,
                        pubKeyBuffer, 
                        &pubKeyBufferLen,
                        &pubKeyBitLen))
    {
        printf("mbedtls_ecp_point_read_binary FAILED\r\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    status = sss_key_store_context_init(&sssPubKeySlot, &sssSessionSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init FAILED, 0x%x\r\n", status);
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanUp;
    }

    status = sss_key_store_allocate(&sssPubKeySlot, TMP_KEY_SLOT);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_allocate FAILED, 0x%x\r\n", status);
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanUp;
    }

    status = sss_key_object_init(&sssPubKeyObject, &sssPubKeySlot);
    if (status != kStatus_SSS_Success) 
    {
        printf(" sss_key_object_init for otherPartyKeyObject Failed\r\n");
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanUp;
    }

    status = sss_key_object_allocate_handle(&sssPubKeyObject,
                                            TMP_KEY_SLOT,
                                            kSSS_KeyPart_Public,
                                            pubKeyType,
                                            (sizeof(pubKeyBuffer)),
                                            kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success) 
    {
        printf(" sss_key_object_allocate_handle for otherPartyKeyObject Failed\r\n");
        ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
        goto cleanUp;
    }

    status = sss_key_store_set_key(&sssPubKeySlot,
                                   &sssPubKeyObject,
                                   pubKeyBuffer,
                                   pubKeyBufferLen,
                                   pubKeyBitLen,
                                   NULL,
                                   0);
    if (status != kStatus_SSS_Success) 
    {
        printf(" sss_key_store_set_key  for public key Failed, 0x%x\r\n", status);
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanUp;
    }

    if(parseMpiToAsn1(r, s, signature, &signatureLen))
    {
        printf("parseMpiToAsn1 Failed...\r\n");
        goto cleanUp;
    }

    defineEcdsaHashAlgorithm(&sssEcdsaHashAlgorithm, blen);
    if(sssEcdsaHashAlgorithm == NULL)
    {
        return -1;
    }

    status = sss_asymmetric_context_init(&sssAsymmetricCtx,
                                         &sssSessionSE,
                                         &sssPubKeyObject,
                                         sssEcdsaHashAlgorithm,
                                         kMode_SSS_Verify);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_asymmetric_context_init FAILED, 0x%x\r\n", status);
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanUp;
    }

    status = sss_asymmetric_verify_digest(&sssAsymmetricCtx,
                                          buf,
                                          blen,
                                          signature,
                                          signatureLen);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_asymmetric_verify_digest FAILED, 0x%x\r\n", status);
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanUp;
    }

cleanUp:
    sss_key_store_erase_key(&sssPubKeySlot, &sssPubKeyObject);
    sss_key_store_context_free(&sssPubKeySlot);
    sss_asymmetric_context_free(&sssAsymmetricCtx);
    sss_key_object_free(&sssPubKeyObject);

    return ret;
}

#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_VERIFY_ALT) && SSS_HAVE_ALT_SSS */

#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_ALT) && SSS_HAVE_ALT_SSS

extern int mbedtls_ecdh_gen_public_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *d,
    mbedtls_ecp_point *Q,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);
extern int mbedtls_ecdh_compute_shared_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng);LOG_E(
extern int mbedtls_ecdh_get_params_o(mbedtls_ecdh_context *ctx,
    const mbedtls_ecp_keypair *key,
    mbedtls_ecdh_side side);

/*
 * Generate public key: simple wrapper around mbedtls_ecp_gen_keypair
 */
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp,
    mbedtls_mpi *d,
    mbedtls_ecp_point *Q,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    sss_status_t status = kStatus_SSS_Success;
    uint8_t publickey[256] = {0};
    int headerLen = 0;
    size_t publickeylen = sizeof(publickey);
    size_t publickeyBitLen = publickeylen * 8;

    /* Check whether the ecc curve is supported by the SE050*/
    if (get_header_and_bit_Length(grp->id, &headerLen, NULL))
    {
        return -1;
    }

    /* Slot for the ephemeral key */
    status = sss_key_store_context_init(&sssEphemeralKey, &sssSessionSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init FAILED, 0x%x\n", status);
        return -1; //TODO_scpf find hardware error 
    }

    status = sss_key_store_allocate(&sssEphemeralKey, EPHEMERAL_KEY_SLOT);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_allocate FAILED, 0x%x\n", status);
        return -1; //TODO_scpf find hardware error 
    }

    status = sss_key_object_init(&sssEphemeralObject, &sssEphemeralKey);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_key_object_init FAILED, 0x%x\n", status);
        return -1; //TODO_scpf find hardware error 
    }

    /* TODO_scpf 
     * * Use information about the key from the grp parameter 
     */
    status = sss_key_object_allocate_handle(&sssEphemeralObject, 
                                            EPHEMERAL_KEY_SLOT, 
                                            kSSS_KeyPart_Pair,
                                            kSSS_CipherType_EC_NIST_P,
                                            256,
                                            kKeyObject_Mode_Persistent);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_key_object_allocate_handle FAILED, 0x%x\n", status);
        return -1; //TODO_scpf find hardware error 
    }

    status = sss_key_store_generate_key(&sssEphemeralKey,
                                        &sssEphemeralObject,
                                        256,
                                        NULL);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_generate_key FAILED, 0x%x\n", status);
        return -1;
    }

    status = sss_key_store_get_key(&sssEphemeralKey,
                                   &sssEphemeralObject,
                                   publickey,
                                   &publickeylen,
                                   &publickeyBitLen);
    if(status != kStatus_SSS_Success)
    {   
        printf("sss_key_store_get_key FAILED, 0x%x\n", status);
        return status;
    }else
    {
        publickeylen -= headerLen;

        if(mbedtls_ecp_point_read_binary(grp, 
                                         Q, 
                                         &publickey[headerLen], 
                                         publickeylen))
        {
            printf("mbedtls_ecp_point_read_binary FAILED\r\n");
            return -1;
        }
    }

    return (0);
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret = 1;
    int headerLen = 0;
    uint8_t OtherPublicKey[256];
    size_t OtherPublickeylen = sizeof(OtherPublicKey);
    int keyBitLen = 0;
    sss_status_t status;
    sss_object_t OtherPartyKeyObject;
    sss_key_store_t OtherPartyKeyStore;
    sss_derive_key_t context;
    uint8_t SharedSecret[128];
    uint16_t SharedSecretlen = sizeof(SharedSecret);
    uint8_t buf[256];
    size_t bitLen = 500;
    size_t bufByteLen = sizeof(buf);
    sss_cipher_type_t OtherPublickeycipherType = kSSS_CipherType_NONE;

    if(get_header_and_bit_Length(grp->id, &headerLen, &keyBitLen)) 
    {
        return 1;
    }

    else if(sssEphemeralObject.cipherType == kSSS_CipherType_EC_NIST_P ||
            sssEphemeralObject.cipherType == kSSS_CipherType_EC_NIST_K ||
            sssEphemeralObject.cipherType == kSSS_CipherType_EC_BRAINPOOL ||
            sssEphemeralObject.cipherType == kSSS_CipherType_EC_MONTGOMERY ||
            sssEphemeralObject.cipherType == kSSS_CipherType_EC_TWISTED_ED) {
        if (0 == mbedtls_ecp_point_write_binary(grp,
                     Q,
                     MBEDTLS_ECP_PF_UNCOMPRESSED,
                     &OtherPublickeylen,
                     (OtherPublicKey + headerLen),
                     sizeof(OtherPublicKey))) {
            switch (grp->id) {
            case MBEDTLS_ECP_DP_SECP192R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_nist192,
                    der_ecc_nistp192_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_nistp192_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP224R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_nist224,
                    der_ecc_nistp224_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_nistp224_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP256R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_nist256,
                    der_ecc_nistp256_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_nistp256_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP384R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_nist384,
                    der_ecc_nistp384_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_nistp384_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_SECP521R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_nist521,
                    der_ecc_nistp521_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_nistp521_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_P;
                break;
            case MBEDTLS_ECP_DP_BP256R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_bp256,
                    der_ecc_bp256_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_bp256_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
                break;
            case MBEDTLS_ECP_DP_BP384R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_bp384,
                    der_ecc_bp384_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_bp384_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
                break;
            case MBEDTLS_ECP_DP_BP512R1:
                memcpy(OtherPublicKey,
                    gecc_der_header_bp512,
                    der_ecc_bp512_header_len);
                OtherPublickeylen =
                    OtherPublickeylen + der_ecc_bp512_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_BRAINPOOL;
                break;
            case MBEDTLS_ECP_DP_SECP192K1:
                memcpy(OtherPublicKey,
                    gecc_der_header_192k,
                    der_ecc_192k_header_len);
                OtherPublickeylen = OtherPublickeylen + der_ecc_192k_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
                break;
            case MBEDTLS_ECP_DP_SECP224K1:
                memcpy(OtherPublicKey,
                    gecc_der_header_224k,
                    der_ecc_224k_header_len);
                OtherPublickeylen = OtherPublickeylen + der_ecc_224k_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
                break;
            case MBEDTLS_ECP_DP_SECP256K1:
                memcpy(OtherPublicKey,
                    gecc_der_header_256k,
                    der_ecc_256k_header_len);
                OtherPublickeylen = OtherPublickeylen + der_ecc_256k_header_len;
                OtherPublickeycipherType = kSSS_CipherType_EC_NIST_K;
                break;
            default:
                return 1;
            }

            printf("\r\nPublic key parameters: curve %d, key length %d, key bit length %d\r\n", 
                    OtherPublickeycipherType, OtherPublickeylen, keyBitLen);
            
            cryptoLog(OtherPublicKey, sizeof(OtherPublicKey));

            do {
                /* Slot for the session key */
                status = sss_key_store_context_init(&sssSessionKey, &sssSessionSE);
                if(status != kStatus_SSS_Success)
                {
                    printf("sss_key_store_context_init FAILED, 0x%x\n", status);
                    return -1; //TODO_scpf find hardware error 
                }

                status = sss_key_store_allocate(&sssSessionKey, SESSION_KEY_SLOT);
                if(status != kStatus_SSS_Success)
                {
                    printf("sss_key_store_allocate FAILED, 0x%x\n", status);
                    return -1; //TODO_scpf find hardware error 
                }

                // For The derived shared secret init and allocate
                status = sss_key_object_init(&sssSessionObject, &sssSessionKey);
                if (status != kStatus_SSS_Success) {
                    printf(
                        " sss_key_object_init for sssSessionObject "
                        "Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_key_object_allocate_handle(&sssSessionObject,
                    SESSION_KEY_SLOT,
                    kSSS_KeyPart_Default,
                    kSSS_CipherType_HMAC,
                    SharedSecretlen,
                    kKeyObject_Mode_Persistent);
                if (status != kStatus_SSS_Success) {
                    LOG_E(
                        " sss_key_object_allocate_handle for sssSessionObject "
                        "Failed");
                    ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
                    break;
                }

                /* Slot for the other partys public key */
                status = sss_key_store_context_init(&OtherPartyKeyStore, &sssSessionSE);
                if(status != kStatus_SSS_Success)
                {
                    printf("sss_key_store_context_init FAILED, 0x%x\n", status);
                    return -1; //TODO_scpf find hardware error 
                }

                status = sss_key_store_allocate(&OtherPartyKeyStore, OTHER_PARTY_KEY_SLOT);
                if(status != kStatus_SSS_Success)
                {
                    printf("sss_key_store_allocate FAILED, 0x%x\n", status);
                    return -1; //TODO_scpf find hardware error 
                }

                //  SSCP Transient Object for the othe party public key init and allocate
                status = sss_key_object_init(&OtherPartyKeyObject, &OtherPartyKeyStore);
                if (status != kStatus_SSS_Success) {
                    LOG_E(
                        " sss_key_object_init for otherPartyKeyObject "
                        "Failed");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_key_object_allocate_handle(&OtherPartyKeyObject,
                    OTHER_PARTY_KEY_SLOT,
                    kSSS_KeyPart_Public,
                    OtherPublickeycipherType,
                    (sizeof(OtherPublicKey)),
                    kKeyObject_Mode_Transient);
                if (status != kStatus_SSS_Success) {
                    LOG_E(
                        " sss_key_object_allocate_handle for "
                        "otherPartyKeyObject Failed");
                    ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
                    break;
                }

                //setting  the other party public key
                status = sss_key_store_set_key(&OtherPartyKeyStore,
                    &OtherPartyKeyObject,
                    OtherPublicKey,
                    OtherPublickeylen,
                    keyBitLen,
                    NULL,
                    0);
                if (status != kStatus_SSS_Success) {
                    LOG_E("\r\n################## sss_key_store_set_key  for keyPair Failed ##################\r\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_derive_key_context_init(&context,
                    &sssSessionSE,
                    &sssEphemeralObject,
                    kAlgorithm_SSS_ECDH,
                    kMode_SSS_ComputeSharedSecret);
                if (status != kStatus_SSS_Success) {
                    printf(" sss_derive_key_context_init Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                status = sss_derive_key_dh(
                    &context, &OtherPartyKeyObject, &sssSessionObject);
                if (status != kStatus_SSS_Success) {
                    printf(" sss_derive_key_dh Failed...\n");
                    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                    break;
                }

                // status = sss_key_store_get_key(
                //     &sssSessionKey, &sssSessionObject, buf, &bufByteLen, &bitLen);
                // if (status != kStatus_SSS_Success) {
                //     printf(" sss_key_store_get_key Failed..., %0x%x\n", status);
                //     ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
                //     break;
                // }
                // ret = mbedtls_mpi_read_binary(z, buf, bufByteLen);
                ret = 0;
            } while (0);
            sss_key_object_free(&OtherPartyKeyObject);
            sss_derive_key_context_free(&context);
        }
    }
    else {
        ret = 1; //Failed
    }
    return (ret);
}

#if defined(MBEDTLS_PRF_ALT) && SSS_HAVE_ALT_SSS

/* Fallback function from mbedTLS */
static int tls_prf_generic_o( mbedtls_md_type_t md_type,
                              const unsigned char *secret, size_t slen,
                              const char *label,
                              const unsigned char *random, size_t rlen,
                              unsigned char *dstbuf, size_t dlen )
{
    size_t nb;
    size_t i, j, k, md_len;
    unsigned char *tmp;
    size_t tmp_len = 0;
    unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    int ret;

    mbedtls_md_init( &md_ctx );

    if( ( md_info = mbedtls_md_info_from_type( md_type ) ) == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    md_len = mbedtls_md_get_size( md_info );

    tmp_len = md_len + strlen( label ) + rlen;
    tmp = mbedtls_calloc( 1, tmp_len );
    if( tmp == NULL )
    {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }

    nb = strlen( label );
    memcpy( tmp + md_len, label, nb );
    memcpy( tmp + md_len + nb, random, rlen );
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    if ( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        goto exit;

    mbedtls_md_hmac_starts( &md_ctx, secret, slen );
    mbedtls_md_hmac_update( &md_ctx, tmp + md_len, nb );
    mbedtls_md_hmac_finish( &md_ctx, tmp );

    for( i = 0; i < dlen; i += md_len )
    {
        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, md_len + nb );
        mbedtls_md_hmac_finish( &md_ctx, h_i );

        mbedtls_md_hmac_reset ( &md_ctx );
        mbedtls_md_hmac_update( &md_ctx, tmp, md_len );
        mbedtls_md_hmac_finish( &md_ctx, tmp );

        k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

exit:
    mbedtls_md_free( &md_ctx );

    mbedtls_platform_zeroize( tmp, tmp_len );
    mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

    mbedtls_free( tmp );

    return( ret );
}

int tls_prf_generic( mbedtls_md_type_t md_type,
                     const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    sss_status_t status = kStatus_SSS_Success;
    sss_derive_key_t context;
    uint8_t hkdfOutput[256] = {0};
    size_t hkdfOutputLen = sizeof(hkdfOutput);

    printf("\r\nRequested length is %d\r\n", dlen);

    if(!strcmp(label, "extended master secret"))
    {
        /* Derive master secret */
        printf("extended master secret, slen = %d", slen);
        /* Slot to store the master secret */
        status = sss_key_store_context_init(&sssMasterSecretKey, &sssSessionSE);
        if(status != kStatus_SSS_Success)
        {
            printf("sss_key_store_context_init FAILED, 0x%x\n", status);
            return -1; //TODO_scpf find hardware error 
        }

        status = sss_key_store_allocate(&sssMasterSecretKey, MASTER_SECRET_KEY_SLOT);
        if(status != kStatus_SSS_Success)
        {
            printf("sss_key_store_allocate FAILED, 0x%x\n", status);
            return -1; //TODO_scpf find hardware error 
        }

        status = sss_key_object_init(&sssMasterSecretObject, &sssMasterSecretKey);
        if (status != kStatus_SSS_Success) {
            printf(
                " sss_key_object_init for sssSessionObject "
                "Failed...\n");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        status = sss_key_object_allocate_handle(&sssMasterSecretObject,
                                                MASTER_SECRET_KEY_SLOT,
                                                kSSS_KeyPart_Default,
                                                kSSS_CipherType_HMAC,
                                                dlen,
                                                kKeyObject_Mode_Persistent);
        if (status != kStatus_SSS_Success) {
            LOG_E(
                " sss_key_object_allocate_handle for sssMasterSecretObject "
                "Failed");
            return MBEDTLS_ERR_ECP_ALLOC_FAILED;
        }

        status = sss_derive_key_context_init(&context,
                                             &sssSessionSE,
                                             &sssSessionObject,
                                             kAlgorithm_SSS_SHA256,
                                             kMode_SSS_Digest);
        if (status != kStatus_SSS_Success) {
            printf(" sss_derive_key_context_init Failed...\n");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
        
        status = sss_derive_key_go(&context,
                                   random,
                                   rlen,
                                   label,
                                   strlen(label),
                                   &sssMasterSecretObject,
                                   dlen,
                                   hkdfOutput,
                                   &hkdfOutputLen);
        if (status != kStatus_SSS_Success) {
            printf(" sss_derive_key_go Failed...\n");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        sss_derive_key_context_free(&context);
    }else if(!strcmp(label, "key expansion"))
    {
        /* Derive symmetric keys */
        printf("key expansion, slen = %d", slen);
        sss_key_store_t  sssDerivedKey;
        sss_object_t     sssDerivedObject;
        status = sss_key_store_context_init(&sssDerivedKey, &sssSessionSE);
        if(status != kStatus_SSS_Success)
        {
            printf("sss_key_store_context_init FAILED, 0x%x\n", status);
            return -1; //TODO_scpf find hardware error 
        }

        status = sss_key_store_allocate(&sssDerivedKey, 254);
        if(status != kStatus_SSS_Success)
        {
            printf("sss_key_store_allocate FAILED, 0x%x\n", status);
            return -1; //TODO_scpf find hardware error 
        }

        status = sss_key_object_init(&sssDerivedObject, &sssDerivedKey);
        if (status != kStatus_SSS_Success) {
            printf(
                " sss_key_object_init for sssSessionObject "
                "Failed...\n");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        status = sss_key_object_allocate_handle(&sssDerivedObject,
                                                254,
                                                kSSS_KeyPart_Default,
                                                kSSS_CipherType_AES,
                                                32,
                                                kKeyObject_Mode_Transient);
        if (status != kStatus_SSS_Success) {
            LOG_E(
                " sss_key_object_allocate_handle for sssMasterSecretObject "
                "Failed");
            return MBEDTLS_ERR_ECP_ALLOC_FAILED;
        }

        status = sss_derive_key_context_init(&context,
                                             &sssSessionSE,
                                             &sssMasterSecretObject,
                                             kAlgorithm_SSS_SHA256,
                                             kMode_SSS_Digest);
        if (status != kStatus_SSS_Success) {
            printf(" sss_derive_key_context_init Failed...\n");
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        /* To get the key from a AES object, the length has to be 32 bytes! */
        size_t totalSize = 0;
        size_t bitSizePerRound = 256;
        size_t size = 32;

        do
        {
            status = sss_derive_key_go(&context,
                                       random,
                                       rlen,
                                       label,
                                       strlen(label),
                                       &sssDerivedObject,
                                       32,
                                       hkdfOutput,
                                       &hkdfOutputLen);
            if (status != kStatus_SSS_Success) {
                printf(" sss_derive_key_go Failed...\n");
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            
            printf("\r\ncheck hkdfOutput\r\n");
            cryptoLog(hkdfOutput, hkdfOutputLen);

            // status = sss_key_store_get_key(
            //     &sssDerivedKey, &sssDerivedObject, &dstbuf[totalSize], &size, &bitSizePerRound);
            // if (status != kStatus_SSS_Success) {
            //     printf(" sss_key_store_get_key Failed..., 0x%x\n", status);
            //     return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            // }

            if(hkdfOutputLen != 32)
            {
                printf("Key size read not correct, %d\r\n", bitSizePerRound);
                break;
            }else
            {
                memcpy(&dstbuf[totalSize], hkdfOutput, hkdfOutputLen);
                totalSize += hkdfOutputLen;
            }
            hkdfOutputLen = sizeof(hkdfOutput);
            printf("YEAHH we did one round :)\r\n");
        } while (totalSize < dlen);
        
        cryptoLog(dstbuf, dlen);

        sss_key_object_free(&sssDerivedObject);
        sss_derive_key_context_free(&context);
    }else
    {
        /* Use original mbedTLS function */
        printf("Fallback\r\n");
        return tls_prf_generic_o(md_type, secret, slen, label, random, rlen, dstbuf, dlen );
    }

    return (0);
}

#endif /* defined(MBEDTLS_PRF_ALT) && SSS_HAVE_ALT_SSS */

/*
 * Get parameters from a keypair
 */
int mbedtls_ecdh_get_params(mbedtls_ecdh_context *ctx,
    const mbedtls_ecp_keypair *key,
    mbedtls_ecdh_side side)
{
    int ret;

    // sss_object_t *backup_type_SSS_Object = ctx->grp.pSSSObject;
    // sss_key_store_t *backup_type_hostKs = ctx->grp.hostKs;
    ret = mbedtls_ecdh_get_params_o(ctx, key, side);
    // ctx->grp.pSSSObject = backup_type_SSS_Object;
    // ctx->grp.hostKs = backup_type_hostKs;
    return (ret);
}

#endif /* defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_ALT) && SSS_HAVE_ALT_SSS */

#if defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT) && SSS_HAVE_ALT_SSS

static int se050Provision(void)
{
    int ret = 0;
    sss_status_t status = kStatus_SSS_Success;

    /* Store the private key */
    status = sss_key_store_context_init(&sssCertKey, &sssSessionSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init FAILED for cert private key, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_store_allocate(&sssCertKey, CLIENT_KEY_SLOT);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_allocate FAILED for cert private key, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_object_init(&sssCertKeyObject, &sssCertKey);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_object_init FAILED for cert private key, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_object_allocate_handle(&sssCertKeyObject,
                                            CLIENT_KEY_SLOT,
                                            kSSS_KeyPart_Pair,
                                            kSSS_CipherType_EC_NIST_P,
                                            sizeof(clientKey),
                                            kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_object_allocate_handle for cert private key FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_store_set_key(&sssCertKey,
                                   &sssCertKeyObject,
                                   clientKey,
                                   sizeof(clientKey),
                                   256,
                                   NULL,
                                   0);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_store_set_key for cert private key FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    /* Store the CA certificate */

    status = sss_key_store_context_init(&sssCaSlot, &sssSessionSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init for CA cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_store_allocate(&sssCaSlot, CA_CERTIFICATE_SLOT);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_allocate for CA cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_object_init(&sssCaObject, &sssCaSlot);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_object_init for CA cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_object_allocate_handle(&sssCaObject,
                                            CA_CERTIFICATE_SLOT,
                                            kSSS_KeyPart_Default,
                                            kSSS_CipherType_Binary,
                                            sizeof(caCert),
                                            kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) 
    {
        printf("sss_key_object_allocate_handle for CA cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_store_set_key(&sssCaSlot,
                                   &sssCaObject,
                                   caCert,
                                   sizeof(caCert),
                                   sizeof(caCert) * 8,
                                   NULL,
                                   0);
    if (status != kStatus_SSS_Success) 
    {
        printf("sss_key_store_set_key for CA cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    /* Store client certificate */

    status = sss_key_store_context_init(&sssCertSlot, &sssSessionSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_context_init for cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_store_allocate(&sssCertSlot, CLIENT_CERTIFICATE_SLOT);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_key_store_allocate for cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_object_init(&sssCertObject, &sssCertSlot);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_object_init for cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_object_allocate_handle(&sssCertObject,
                                            CLIENT_CERTIFICATE_SLOT,
                                            kSSS_KeyPart_Default,
                                            kSSS_CipherType_Binary,
                                            sizeof(clientCert),
                                            kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_object_allocate_handle for cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    status = sss_key_store_set_key(&sssCertSlot,
                                   &sssCertObject,
                                   clientCert,
                                   sizeof(clientCert),
                                   sizeof(clientCert) * 8,
                                   NULL,
                                   0);
    if (status != kStatus_SSS_Success) {
        printf("sss_key_store_set_key for cert FAILED, 0x%x\n", status);
        ret = -1;
        goto cleanUp;
    }

    provisionState = 1;

cleanUp:
    sss_key_store_context_free(&sssCertKey);
    sss_key_object_free(&sssCertKeyObject);

    sss_key_store_context_free(&sssCaSlot);
    sss_key_object_free(&sssCaObject);
    
    sss_key_store_context_free(&sssCertSlot);
    sss_key_object_free(&sssCertObject);

    return ret;
}

int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
    int ret = 0;
    sss_status_t status = kStatus_SSS_Success;

    /**
     * Create host session for encrypted communication between the LPC55S69 and 
     * the SE050
     */
    // sssConnectionDataHost.connType = kType_SE_Conn_Type_T1oI2C;
    // sssConnectionDataHost.portName = NULL;
    // print_memory_info();
    // status = ex_sss_se05x_prepare_host(&sssHostSession, 
    //                                    &sssHostKeyStore, 
    //                                    &sssConnectionDataHost,
    //                                    &sssHostAuthCtx,
    //                                    kSSS_AuthType_SCP03);
    // if(status != kStatus_SSS_Success)
    // {
    //     printf("ex_sss_se_prepare_host FAILED, 0x%x\n", status);
    //     return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    // }
    /**
     * Create SE session for encrypted communication between the LPC55S69 and 
     * the SE050
     */
    status = sss_session_create(&sssSessionSE, 
                                kType_SSS_SE_SE05x, 
                                0, 
                                kSSS_ConnectionType_Plain, 
                                &sssConnectionDataSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_session_create FAILED, 0x%x\n", status);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    status = sss_session_open(&sssSessionSE, 
                              kType_SSS_SE_SE05x, 
                              0, 
                              kSSS_ConnectionType_Plain, 
                              &sssConnectionDataSE);
    if(status != kStatus_SSS_Success)
    {
        printf("sss_session_open FAILED, 0x%x\n", status);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    // if(provisionState < 1)
    // {
    //     if(se050Provision() < 0)
    //     {
    //         printf("Provisioning FAILED!\n");
    //         return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    //     }

    //     printf("se050Provision SUCCESS\r\n");
    // }else 
    // {
    //     printf("SE050 already provisioned\r\n");
    // }

    return( 0 );
}

/*
 * Placeholder platform teardown that does nothing by default
 */
void mbedtls_platform_teardown( mbedtls_platform_context *ctx )
{
    sss_session_close(&sssSessionSE);
}

#endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT && SSS_HAVE_ALT_SSS */
