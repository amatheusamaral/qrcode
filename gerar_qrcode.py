import qrcode

data = "https://www.youtube.com/watch?v=sKYl37T2ZbU"

img = qrcode.make(data)

img.save("qrcode_teste.png")