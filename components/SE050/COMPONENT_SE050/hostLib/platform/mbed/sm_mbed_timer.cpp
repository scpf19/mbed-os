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
 * \file        mqtt_utils.cpp
 *
 * \description Module maps the timer functions required by the PLUG & TRUST MW 
 *              firmware to Mbed OS.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        04.12.2019
 *
 *****************************************************************************/

#include "mbed.h"

#include "sm_timer.h"
#include "fsl_ctimer.h"
#include "PeripheralNames.h"

static void s_ticker_irq_handler(void)
{

}

uint32_t sm_initSleep(void)
{
    //printf("hello from sm_initSleep\r\n");
    //ctimer_config_t config;

    //uint32_t pclk = CLOCK_GetFreq(kCLOCK_BusClk);
    //uint32_t prescale = pclk / 1000000;

    // CTIMER_GetDefaultConfig(&config);
    // config.prescale = 1;
    // CTIMER_Init(CTIMER0, &config);
    // CTIMER_Reset(CTIMER0);
    // CTIMER_StartTimer(CTIMER0);
    // printf("hello from the middle\n");
    // NVIC_SetVector(CTIMER0_IRQn, (uint32_t)s_ticker_irq_handler);
    // NVIC_EnableIRQ(CTIMER0_IRQn);
    // CTIMER0->MCR &= ~1;

    return 0;
}

void sm_sleep(uint32_t msec)
{
    printf("hello from sm_sleep, %d\r\n", msec*1000);
    //wait_us(msec*1000);
}

void sm_usleep(uint32_t microsec)
{
    printf("hello from sm_us_sleep\r\n");
    //wait_us(microsec);
}