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
 * \file        i2c_mbed.cpp
 *
 * \description Module maps the i2c functions required by the PLUG & TRUST MW 
 *              firmware to Mbed OS.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        04.12.2019
 *
 *****************************************************************************/

#include "mbed.h"

#include "i2c_a7.h"

static I2C *i2cMbed;
static uint32_t i2cBackOffDelay;

i2c_error_t axI2CInit(void)
{
    i2cMbed = new I2C(MBED_CONF_SE050_SSS_LIB_I2C_SDA, 
                      MBED_CONF_SE050_SSS_LIB_I2C_SCL);

    i2cMbed->frequency(MBED_CONF_SE050_SSS_LIB_FREQUENCY);

    return I2C_OK;
}

void axI2CTerm(int mode)
{  

}

void axI2CResetBackoffDelay(void)
{
    i2cBackOffDelay = 0;
}

i2c_error_t axI2CWriteRead(unsigned char bus_unused_param,
                           unsigned char addr,
                           unsigned char *pTx,
                           unsigned short txLen,
                           unsigned char *pRx,
                           unsigned short *pRxLen)
{
    return I2C_FAILED;
}

i2c_error_t axI2CWrite(unsigned char bus_unused_param, 
                       unsigned char addr, 
                       unsigned char *pTx, 
                       unsigned short txLen)
{
    int ret = 0;

    ret = i2cMbed->write(addr, (char*)pTx, txLen);
    if(ret != 0)
    {
        printf("axI2CWrite returned %d\n", ret);
        return I2C_FAILED;
    }

    return I2C_OK;
}

i2c_error_t axI2CRead(unsigned char bus, 
                      unsigned char addr, 
                      unsigned char *pRx, 
                      unsigned short rxLen)
{
    int ret = 0;

    ret = i2cMbed->read(addr, (char*)pRx, rxLen);
    if(ret != 0)
    {
        return I2C_FAILED;
    }

    return I2C_OK;
}