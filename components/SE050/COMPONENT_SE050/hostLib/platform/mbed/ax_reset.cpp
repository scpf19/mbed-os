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
 * \file        ax_reset.cpp
 *
 * \description Module maps the reset functions required by the PLUG & TRUST MW 
 *              firmware to Mbed OS.
 *
 * \author      Tobias Schläpfer (scpf)
 *
 * \date        04.12.2019
 *
 *****************************************************************************/

#include "mbed.h"

#include "sm_timer.h"
#include "ax_reset.h"

DigitalOut seResetGpio(MBED_CONF_SE050_SSS_LIB_RESET);

void axReset_HostConfigure(void)
{}

void axReset_ResetPluseDUT()
{
    axReset_PowerDown();
    sm_usleep(2000);
    axReset_PowerUp();
}

void axReset_PowerDown(void)
{
    seResetGpio = 0;
}

void axReset_PowerUp(void)
{
    seResetGpio = 1;
}