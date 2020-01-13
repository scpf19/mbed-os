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
 * \file        platform_alt.h
 *
 * \description Module implements a set of cryptographic operations using the 
 *              SE050 and provides these function for the SE driver in the TF-M.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        17.12.2019
 *
 *****************************************************************************/

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "fsl_sss_api.h"
#include "nxScp03_Types.h"

#if defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT) && SSS_HAVE_ALT_SSS

typedef struct mbedtls_platform_context
{
    sss_session_t     sssSession;
    SE_Connect_Ctx_t  sssConnectionData;
    sss_key_store_t   sssClientKey;
    sss_key_store_t   sssClientCert;
    sss_key_store_t   sssCaCert;
    sss_key_store_t   sssEphemeral;
    sss_key_store_t   sssSessionKey;
    sss_object_t      sssClientKeyObject;
    sss_object_t      sssClientCertObject;
    sss_object_t      sssCaCertObject;
    sss_object_t      sssEphemeralObject;
    sss_object_t      sssSessionObject;
}
mbedtls_platform_context;

#endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT && SSS_HAVE_ALT_SSS */