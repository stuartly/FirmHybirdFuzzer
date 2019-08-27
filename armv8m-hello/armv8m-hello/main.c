#include <stdint.h>

typedef enum IRQn {
  /* Auxiliary constants */
  NotAvail_IRQn                = -128,             /**< Not available device specific interrupt */

  /* Core interrupts */
  NonMaskableInt_IRQn          = -14,              /**< Non Maskable Interrupt */
  HardFault_IRQn               = -13,              /**< Cortex-M4 SV Hard Fault Interrupt */
  MemoryManagement_IRQn        = -12,              /**< Cortex-M4 Memory Management Interrupt */
  BusFault_IRQn                = -11,              /**< Cortex-M4 Bus Fault Interrupt */
  UsageFault_IRQn              = -10,              /**< Cortex-M4 Usage Fault Interrupt */
  SVCall_IRQn                  = -5,               /**< Cortex-M4 SV Call Interrupt */
  DebugMonitor_IRQn            = -4,               /**< Cortex-M4 Debug Monitor Interrupt */
  PendSV_IRQn                  = -2,               /**< Cortex-M4 Pend SV Interrupt */
  SysTick_IRQn                 = -1,               /**< Cortex-M4 System Tick Interrupt */

  /* Device specific interrupts */
  DMA0_DMA16_IRQn              = 0,                /**< DMA Channel 0, 16 Transfer Complete */
  DMA1_DMA17_IRQn              = 1,                /**< DMA Channel 1, 17 Transfer Complete */
  DMA2_DMA18_IRQn              = 2,                /**< DMA Channel 2, 18 Transfer Complete */
  DMA3_DMA19_IRQn              = 3,                /**< DMA Channel 3, 19 Transfer Complete */
  DMA4_DMA20_IRQn              = 4,                /**< DMA Channel 4, 20 Transfer Complete */
  DMA5_DMA21_IRQn              = 5,                /**< DMA Channel 5, 21 Transfer Complete */
  DMA6_DMA22_IRQn              = 6,                /**< DMA Channel 6, 22 Transfer Complete */
  DMA7_DMA23_IRQn              = 7,                /**< DMA Channel 7, 23 Transfer Complete */
  DMA8_DMA24_IRQn              = 8,                /**< DMA Channel 8, 24 Transfer Complete */
  DMA9_DMA25_IRQn              = 9,                /**< DMA Channel 9, 25 Transfer Complete */
  DMA10_DMA26_IRQn             = 10,               /**< DMA Channel 10, 26 Transfer Complete */
  DMA11_DMA27_IRQn             = 11,               /**< DMA Channel 11, 27 Transfer Complete */
  DMA12_DMA28_IRQn             = 12,               /**< DMA Channel 12, 28 Transfer Complete */
  DMA13_DMA29_IRQn             = 13,               /**< DMA Channel 13, 29 Transfer Complete */
  DMA14_DMA30_IRQn             = 14,               /**< DMA Channel 14, 30 Transfer Complete */
  DMA15_DMA31_IRQn             = 15,               /**< DMA Channel 15, 31 Transfer Complete */
  DMA_Error_IRQn               = 16,               /**< DMA Error Interrupt */
  MCM_IRQn                     = 17,               /**< Normal Interrupt */
  FTFE_IRQn                    = 18,               /**< FTFE Command complete interrupt */
  Read_Collision_IRQn          = 19,               /**< Read Collision Interrupt */
  LVD_LVW_IRQn                 = 20,               /**< Low Voltage Detect, Low Voltage Warning */
  LLWU_IRQn                    = 21,               /**< Low Leakage Wakeup Unit */
  WDOG_EWM_IRQn                = 22,               /**< WDOG Interrupt */
  RNG_IRQn                     = 23,               /**< RNG Interrupt */
  I2C0_IRQn                    = 24,               /**< I2C0 interrupt */
  I2C1_IRQn                    = 25,               /**< I2C1 interrupt */
  SPI0_IRQn                    = 26,               /**< SPI0 Interrupt */
  SPI1_IRQn                    = 27,               /**< SPI1 Interrupt */
  I2S0_Tx_IRQn                 = 28,               /**< I2S0 transmit interrupt */
  I2S0_Rx_IRQn                 = 29,               /**< I2S0 receive interrupt */
  Reserved46_IRQn              = 30,               /**< Reserved interrupt 46 */
  UART0_RX_TX_IRQn             = 31,               /**< UART0 Receive/Transmit interrupt */
  UART0_ERR_IRQn               = 32,               /**< UART0 Error interrupt */
  UART1_RX_TX_IRQn             = 33,               /**< UART1 Receive/Transmit interrupt */
  UART1_ERR_IRQn               = 34,               /**< UART1 Error interrupt */
  UART2_RX_TX_IRQn             = 35,               /**< UART2 Receive/Transmit interrupt */
  UART2_ERR_IRQn               = 36,               /**< UART2 Error interrupt */
  UART3_RX_TX_IRQn             = 37,               /**< UART3 Receive/Transmit interrupt */
  UART3_ERR_IRQn               = 38,               /**< UART3 Error interrupt */
  ADC0_IRQn                    = 39,               /**< ADC0 interrupt */
  CMP0_IRQn                    = 40,               /**< CMP0 interrupt */
  CMP1_IRQn                    = 41,               /**< CMP1 interrupt */
  FTM0_IRQn                    = 42,               /**< FTM0 fault, overflow and channels interrupt */
  FTM1_IRQn                    = 43,               /**< FTM1 fault, overflow and channels interrupt */
  FTM2_IRQn                    = 44,               /**< FTM2 fault, overflow and channels interrupt */
  CMT_IRQn                     = 45,               /**< CMT interrupt */
  RTC_IRQn                     = 46,               /**< RTC interrupt */
  RTC_Seconds_IRQn             = 47,               /**< RTC seconds interrupt */
  PIT0_IRQn                    = 48,               /**< PIT timer channel 0 interrupt */
  PIT1_IRQn                    = 49,               /**< PIT timer channel 1 interrupt */
  PIT2_IRQn                    = 50,               /**< PIT timer channel 2 interrupt */
  PIT3_IRQn                    = 51,               /**< PIT timer channel 3 interrupt */
  PDB0_IRQn                    = 52,               /**< PDB0 Interrupt */
  USB0_IRQn                    = 53,               /**< USB0 interrupt */
  USBDCD_IRQn                  = 54,               /**< USBDCD Interrupt */
  Reserved71_IRQn              = 55,               /**< Reserved interrupt 71 */
  DAC0_IRQn                    = 56,               /**< DAC0 interrupt */
  MCG_IRQn                     = 57,               /**< MCG Interrupt */
  LPTMR0_IRQn                  = 58,               /**< LPTimer interrupt */
  PORTA_IRQn                   = 59,               /**< Port A interrupt */
  PORTB_IRQn                   = 60,               /**< Port B interrupt */
  PORTC_IRQn                   = 61,               /**< Port C interrupt */
  PORTD_IRQn                   = 62,               /**< Port D interrupt */
  PORTE_IRQn                   = 63,               /**< Port E interrupt */
  SWI_IRQn                     = 64,               /**< Software interrupt */
  SPI2_IRQn                    = 65,               /**< SPI2 Interrupt */
  UART4_RX_TX_IRQn             = 66,               /**< UART4 Receive/Transmit interrupt */
  UART4_ERR_IRQn               = 67,               /**< UART4 Error interrupt */
  Reserved84_IRQn              = 68,               /**< Reserved interrupt 84 */
  Reserved85_IRQn              = 69,               /**< Reserved interrupt 85 */
  CMP2_IRQn                    = 70,               /**< CMP2 interrupt */
  FTM3_IRQn                    = 71,               /**< FTM3 fault, overflow and channels interrupt */
  DAC1_IRQn                    = 72,               /**< DAC1 interrupt */
  ADC1_IRQn                    = 73,               /**< ADC1 interrupt */
  I2C2_IRQn                    = 74,               /**< I2C2 interrupt */
  CAN0_ORed_Message_buffer_IRQn = 75,              /**< CAN0 OR'd message buffers interrupt */
  CAN0_Bus_Off_IRQn            = 76,               /**< CAN0 bus off interrupt */
  CAN0_Error_IRQn              = 77,               /**< CAN0 error interrupt */
  CAN0_Tx_Warning_IRQn         = 78,               /**< CAN0 Tx warning interrupt */
  CAN0_Rx_Warning_IRQn         = 79,               /**< CAN0 Rx warning interrupt */
  CAN0_Wake_Up_IRQn            = 80,               /**< CAN0 wake up interrupt */
  SDHC_IRQn                    = 81,               /**< SDHC interrupt */
  ENET_1588_Timer_IRQn         = 82,               /**< Ethernet MAC IEEE 1588 Timer Interrupt */
  ENET_Transmit_IRQn           = 83,               /**< Ethernet MAC Transmit Interrupt */
  ENET_Receive_IRQn            = 84,               /**< Ethernet MAC Receive Interrupt */
  ENET_Error_IRQn              = 85,               /**< Ethernet MAC Error and miscelaneous Interrupt */
  LPUART0_IRQn                 = 86,               /**< LPUART0 status/error interrupt */
  TSI0_IRQn                    = 87,               /**< TSI0 interrupt */
  TPM1_IRQn                    = 88,               /**< TPM1 fault, overflow and channels interrupt */
  TPM2_IRQn                    = 89,               /**< TPM2 fault, overflow and channels interrupt */
  USBHSDCD_IRQn                = 90,               /**< USBHSDCD, USBHS Phy Interrupt */
  I2C3_IRQn                    = 91,               /**< I2C3 interrupt */
  CMP3_IRQn                    = 92,               /**< CMP3 interrupt */
  USBHS_IRQn                   = 93,               /**< USB high speed OTG interrupt */
  CAN1_ORed_Message_buffer_IRQn = 94,              /**< CAN1 OR'd message buffers interrupt */
  CAN1_Bus_Off_IRQn            = 95,               /**< CAN1 bus off interrupt */
  CAN1_Error_IRQn              = 96,               /**< CAN1 error interrupt */
  CAN1_Tx_Warning_IRQn         = 97,               /**< CAN1 Tx warning interrupt */
  CAN1_Rx_Warning_IRQn         = 98,               /**< CAN1 Rx warning interrupt */
  CAN1_Wake_Up_IRQn            = 99                /**< CAN1 wake up interrupt */
} IRQn_Type;
#define __IOM volatile
#define __OM volatile
typedef struct
{
  __IOM uint32_t ISER[8U];               /*!< Offset: 0x000 (R/W)  Interrupt Set Enable Register */
        uint32_t RESERVED0[24U];
  __IOM uint32_t ICER[8U];               /*!< Offset: 0x080 (R/W)  Interrupt Clear Enable Register */
        uint32_t RSERVED1[24U];
  __IOM uint32_t ISPR[8U];               /*!< Offset: 0x100 (R/W)  Interrupt Set Pending Register */
        uint32_t RESERVED2[24U];
  __IOM uint32_t ICPR[8U];               /*!< Offset: 0x180 (R/W)  Interrupt Clear Pending Register */
        uint32_t RESERVED3[24U];
  __IOM uint32_t IABR[8U];               /*!< Offset: 0x200 (R/W)  Interrupt Active bit Register */
        uint32_t RESERVED4[56U];
  __IOM uint8_t  IP[240U];               /*!< Offset: 0x300 (R/W)  Interrupt Priority Register (8Bit wide) */
        uint32_t RESERVED5[644U];
  __OM  uint32_t STIR;                   /*!< Offset: 0xE00 ( /W)  Software Trigger Interrupt Register */
}  NVIC_Type;

#define SCS_BASE            (0xE000E000UL)
#define NVIC_BASE           (SCS_BASE +  0x0100UL)                    /*!< NVIC Base Address */
#define NVIC                ((NVIC_Type      *)     NVIC_BASE     )   /*!< NVIC configuration struct */


void NVIC_SetPendingIRQ(IRQn_Type IRQn)
{
    NVIC->ISPR[(((uint32_t)IRQn) >> 5UL)] = (uint32_t)(1UL << (((uint32_t)IRQn) & 0x1FUL));
}

void NVIC_EnableIRQ(IRQn_Type IRQn)
{
    NVIC->ISER[(((uint32_t)IRQn) >> 5UL)] = (uint32_t)(1UL << (((uint32_t)IRQn) & 0x1FUL));

}

void main()
{

    NVIC_EnableIRQ(DMA0_DMA16_IRQn);
    //NVIC_SetPendingIRQ(DMA0_DMA16_IRQn);
    while (1);
}
