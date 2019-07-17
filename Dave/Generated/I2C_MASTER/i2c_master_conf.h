/*********************************************************************************************************************
* DAVE APP Name : I2C_MASTER       APP Version: 4.1.28
*
* NOTE:
* This file is generated by DAVE. Any manual modification done to this file will be lost when the code is regenerated.
*********************************************************************************************************************/

/**
 * @cond
 ***********************************************************************************************************************
 *
 * Copyright (c) 2015-2017, Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,are permitted provided that the
 * following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice, this list of conditions and the  following
 *   disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holders nor the names of its contributors may be used to endorse or promote
 *   products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE  FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT  OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * To improve the quality of the software, users are encouraged to share modifications, enhancements or bug fixes
 * with Infineon Technologies AG (dave@infineon.com).
 ***********************************************************************************************************************
 *
 * Change History
 * --------------
 *
 * 2015-02-16:
 *     - Initial version<br>
 *
 * 2017-01-19:
 *     - Add macros for the interrupt nodes
 *
 * @endcond
 *
 */

#ifndef I2C_MASTER_CONF_H
#define I2C_MASTER_CONF_H

/***********************************************************************************************************************
 * HEADER FILES
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * MACROS
 **********************************************************************************************************************/

#define I2C_MASTER_MAJOR_VERSION 4U
#define I2C_MASTER_MINOR_VERSION 1U
#define I2C_MASTER_PATCH_VERSION 28U

#define i2c_master_0_TX_IRQN ((IRQn_Type)93)
#define i2c_master_0_RX_IRQN ((IRQn_Type)91)
#define I2C_MASTER_DMA_TX_ENABLED 0
#define I2C_MASTER_DMA_RX_ENABLED 0
#define I2C_MASTER_DIRECT_TX_ENABLED 0
#define I2C_MASTER_DIRECT_RX_ENABLED 0
#define I2C_MASTER_INTERRUPT_TX_ENABLED 1
#define I2C_MASTER_INTERRUPT_RX_ENABLED 1

#endif /* End of I2C_MASTER_CONF_H */

