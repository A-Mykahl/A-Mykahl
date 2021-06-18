import turtle
import random

#set turtle speed and background color
turtle.speed(0)
turtle.bgcolor('beige')

#User Input section
limit = 0
shape = int(input("Enter Length of side "))
angle = int(input("Enter Angle "))
counter = random.randint(100, 300)

#Mandala Loop
while limit != 500:
    turtle.forward(shape)
    turtle.right(angle)
    turtle.forward(counter)
    turtle.right(angle + 75)
    limit += 1
    shape += .5
    counter -= 1

    #Sets Colors
    if limit == 100:
        turtle.color("yellow")
    elif limit == 200:
        turtle.color("green")
    elif limit == 300:
        turtle.color("red")
    elif limit == 400:
        turtle.color("blue")
else:
    turtle.done()