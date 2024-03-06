
# Implementing a double pendulum in python3

Ok, so I watched this video by coding train: https://www.youtube.com/watch?v=uWzPe_S-RVE and I decided my hand in programming a double pendulum. You can follow my attempt here: https://github.com/personnumber3377/pythondoublependulum

I think that I should implement an n-pendulum system too when I find the motivation. Something similar to this: https://github.com/almayor/n-pendulum , but that is for a future project. The coding train video referenced this resource which you can find here: https://www.myphysicslab.com/pendulum/double-pendulum-en.html

## Initial skeleton

Ok, so I am going to make a simple skeleton:

```
class DoublePendulum:
    def __init__(self, l0, l1, w0, w1, v0, v1) -> None:
        # Constructor. l0 and l1 are the lengths of the massless rods connecting the two balls.
        # w0 and w1 are the weights of the balls. v0 and v1 are the initial angular velocities. (in rads/second)
        
        # Do the basic stuff, such that we can access these variables inside this class too.
        self.l0 = l0
        self.l1 = l1
        self.w0 = w0
        self.w1 = w1
        self.v0 = v0
        self.v1 = v1
    def update(d_t) -> None: # Goes forward in time by d_t
        return # Just a stub for now.
```

## Implementing the equations

Ok, so after a bit of typing, I came up with this:

```


import math
import turtle
import time

RENDER_SCALING = 50

def scale_point(p: tuple) -> tuple:
    # Scales the point by the render scaling.
    return (p[0]*RENDER_SCALING, p[1]*RENDER_SCALING)

class DoublePendulum:
    def __init__(self, l0, l1, w0, w1, v0, v1, a0, a1) -> None:
        # Constructor. l0 and l1 are the lengths of the massless rods connecting the two balls.
        # w0 and w1 are the weights of the balls. v0 and v1 are the initial angular velocities. (in rads/second)
        
        # Do the basic stuff, such that we can access these variables inside this class too.
        self.l0 = l0
        self.l1 = l1
        self.w0 = w0
        self.w1 = w1
        self.v0 = v0
        self.v1 = v1
        # Here a0 and a1 are the initial angles. These will be updated in the update() method.
        self.a0 = a0
        self.a1 = a1
        # These are the angular accelerations.
        self.acceleration0 = 0
        self.acceleration1 = 0
        # These are the angular velocities.
        self.velocity0 = 0
        self.velocity1 = 0
        # Gravitational acceleration. Just set to one for now.
        self.g = 1
    def get_first_point(self) -> tuple: # This returns the position of the center of the first mass.
        # This gets the first point.
        return (math.sin(self.a0) * self.l0, math.cos(self.a0) * self.l1)
    def get_second_point(self) -> tuple:
        # This gets the second point.
        # First get the first point and then use trigonometry to find the second point.
        first_point = self.get_first_point()
        return (math.sin(self.a1) * self.l0 + first_point[0], math.cos(self.a1) * self.l1 + first_point[1])
    def render(self) -> None: # This renders the stuff. (For visualization.)
        # First get the coordinates of the spheres and draw the lines.
        p0 = self.get_first_point()
        p1 = self.get_second_point()
        # Now get the distance between p0 and p1...
        distance = math.sqrt((p0[0]**2) + (p0[1]**2))
        print("Here is the distance: "+str(distance))
        distance = math.sqrt(((p0[0] - p1[0])**2) + ((p0[1] - p1[1])**2))
        print("Here is another distance: "+str(distance))
        # This is to handle the direction in which we render the shit.
        p0 = (p0[0], p0[1]*(-1))
        p1 = (p1[0], p1[1]*(-1))
        turtle.penup()
        turtle.goto((0,0))
        turtle.pendown()
        turtle.goto(scale_point(p0))
        turtle.goto(scale_point(p1))
        turtle.penup()
        turtle.goto(scale_point(p0))
        turtle.dot(60)
        turtle.goto(scale_point(p1))
        turtle.dot(60)
        return
    def update(self, d_t: float) -> None: # Goes forward in time by d_t
        '''
        These are the equations of interest:  	( −g (2 m1 + m2) sin θ1 − m2 g sin(θ1 − 2 θ2) − 2 sin(θ1 − θ2) m2 (θ2'2 L2 + θ1'2 L1 cos(θ1 − θ2)) ) / (L1 * (2 m1 + m2 − m2 cos(2 θ1 − 2 θ2)))

        and the acceleration of the second point is this:

        (2 sin(θ1 − θ2) (θ1'2 L1 (m1 + m2) + g(m1 + m2) cos θ1 + θ2'2 L2 m2 cos(θ1 − θ2))) / (L2 (2 m1 + m2 − m2 cos(2 θ1 − 2 θ2)))



        '''

        # self.acceleration0 = 2*math.sin(self.a0-self.a1)*math.sin(self.a0) - self.w1 * self.g * math.sin(self.a0 - 2 * self.a1)


        acceleration1_dividend_1 = (2 * math.sin(self.a0 - self.a1))
        acceleration1_dividend_2 = ((self.velocity0**2) * self.l0 * (self.w0 + self.w1)) # This is the thing
        acceleration1_dividend_3 = self.g * (self.w0 + self.w1) * math.cos(self.a0)
        acceleration1_dividend_4 = (self.velocity1**2) * self.l1 * self.w1 * math.cos(self.a0 - self.a1)

        acceleration1_divisor = (self.l1*(2*self.w0 + self.w1 - self.w1*math.cos(2*self.a0 - 2*self.a1)))

        # Now just do the shit...

        self.acceleration1 = (acceleration1_dividend_1 * (acceleration1_dividend_2 + acceleration1_dividend_3 + acceleration1_dividend_4)) / (acceleration1_divisor)

        

        # Now calculate the other angular acceleration. (This is the angular acceleration of the first shit.)

        acceleration0_dividend_1 = (-1*self.g*(2*self.w0 + self.w1)*math.sin(self.a0))
        acceleration0_dividend_2 = (self.w1 * self.g * math.sin(self.a0 - 2 * self.a1))
        acceleration0_dividend_3 = (2 * math.sin(self.a0 - self.a1) * self.w1 * ((self.velocity1**2)*self.l1 + (self.velocity0**2) * self.l0 * math.cos(self.a0 - self.a1)))

        acceleration0_divisor = (self.l0*(2*self.w0 + self.w1 - self.w1*math.cos(2*self.a0 - 2*self.a1)))

        self.acceleration0 = (acceleration0_dividend_1 - acceleration0_dividend_2 - acceleration0_dividend_3) / (acceleration0_divisor)



        # Update variables.
        self.velocity1 += self.acceleration1 * d_t # Update velocity.
        # Update angle with angular velocity.
        self.a1 += self.velocity1 * d_t

        # Update variables.
        self.velocity0 += self.acceleration0 * d_t # Update velocity.
        # Update angle with angular velocity.
        self.a0 += self.velocity0 * d_t


        return # Just a stub for now.

def main() -> int:
    turtle.tracer(0,0)
    turtle.speed(0)
    l0 = 2
    l1 = 1
    w0 = 1
    w1 = 1
    v0 = 1
    v1 = 1
    #a0 = math.pi/4
    #a1 = math.pi/4
    a0 = 0
    a1 = math.pi/4
    simulation = DoublePendulum(l0, l1, w0, w1, v0, v1, a0, a1)
    while True:
        #simulation.a0 += 0.03 # Try out the rendering etc..
        simulation.render()
        simulation.update(0.01)
        turtle.update()
        time.sleep(0.01)
        turtle.clear()
    return 0

if __name__=="__main__":
    exit(main())


```

Except there are a couple of bugs. Here is the fixed version:

Here is the fixed version:

```

def scale_point(p: tuple) -> tuple:
    # Scales the point by the render scaling.
    return (p[0]*RENDER_SCALING, p[1]*RENDER_SCALING)

class DoublePendulum:
    def __init__(self, l0, l1, w0, w1, v0, v1, a0, a1) -> None:
        # Constructor. l0 and l1 are the lengths of the massless rods connecting the two balls.
        # w0 and w1 are the weights of the balls. v0 and v1 are the initial angular velocities. (in rads/second)
        
        # Do the basic stuff, such that we can access these variables inside this class too.
        self.l0 = l0
        self.l1 = l1
        self.w0 = w0
        self.w1 = w1
        self.v0 = v0
        self.v1 = v1
        # Here a0 and a1 are the initial angles. These will be updated in the update() method.
        self.a0 = a0
        self.a1 = a1
        # These are the angular accelerations.
        self.acceleration0 = 0
        self.acceleration1 = 0
        # These are the angular velocities.
        self.velocity0 = 0
        self.velocity1 = 0
        # Gravitational acceleration. Just set to one for now.
        self.g = 10
    def get_first_point(self) -> tuple: # This returns the position of the center of the first mass.
        # This gets the first point.
        return (math.sin(self.a0) * self.l0, math.cos(self.a0) * self.l0)
    def get_second_point(self) -> tuple:
        # This gets the second point.
        # First get the first point and then use trigonometry to find the second point.
        first_point = self.get_first_point()
        return (math.sin(self.a1) * self.l1 + first_point[0], math.cos(self.a1) * self.l1 + first_point[1])
    def render(self) -> None: # This renders the stuff. (For visualization.)
        # First get the coordinates of the spheres and draw the lines.
        p0 = self.get_first_point()
        p1 = self.get_second_point()
        # Now get the distance between p0 and p1...
        distance = math.sqrt((p0[0]**2) + (p0[1]**2))
        print("Here is the distance: "+str(distance))
        distance = math.sqrt(((p0[0] - p1[0])**2) + ((p0[1] - p1[1])**2))
        print("Here is another distance: "+str(distance))
        # This is to handle the direction in which we render the shit.
        p0 = (p0[0], p0[1]*(-1))
        p1 = (p1[0], p1[1]*(-1))
        turtle.penup()
        turtle.goto((0,0))
        turtle.pendown()
        turtle.goto(scale_point(p0))
        turtle.goto(scale_point(p1))
        turtle.penup()
        turtle.goto(scale_point(p0))
        turtle.dot(60)
        turtle.goto(scale_point(p1))
        turtle.dot(60)
        return
    def update(self, d_t: float) -> None: # Goes forward in time by d_t
        '''
        These are the equations of interest:  	( −g (2 m1 + m2) sin θ1 − m2 g sin(θ1 − 2 θ2) − 2 sin(θ1 − θ2) m2 (θ2'2 L2 + θ1'2 L1 cos(θ1 − θ2)) ) / (L1 * (2 m1 + m2 − m2 cos(2 θ1 − 2 θ2)))

        and the acceleration of the second point is this:

        (2 sin(θ1 − θ2) (θ1'2 L1 (m1 + m2) + g(m1 + m2) cos θ1 + θ2'2 L2 m2 cos(θ1 − θ2))) / (L2 (2 m1 + m2 − m2 cos(2 θ1 − 2 θ2)))



        '''

        # self.acceleration0 = 2*math.sin(self.a0-self.a1)*math.sin(self.a0) - self.w1 * self.g * math.sin(self.a0 - 2 * self.a1)


        acceleration1_dividend_1 = (2 * math.sin(self.a0 - self.a1))
        acceleration1_dividend_2 = ((self.velocity0**2) * self.l0 * (self.w0 + self.w1)) # This is the thing
        acceleration1_dividend_3 = self.g * (self.w0 + self.w1) * math.cos(self.a0)
        acceleration1_dividend_4 = (self.velocity1**2) * self.l1 * self.w1 * math.cos(self.a0 - self.a1)

        acceleration1_divisor = (self.l1*(2*self.w0 + self.w1 - self.w1*math.cos(2*self.a0 - 2*self.a1)))

        # Now just do the shit...

        self.acceleration1 = (acceleration1_dividend_1 * (acceleration1_dividend_2 + acceleration1_dividend_3 + acceleration1_dividend_4)) / (acceleration1_divisor)

        

        # Now calculate the other angular acceleration. (This is the angular acceleration of the first shit.)

        acceleration0_dividend_1 = (-1*self.g*(2*self.w0 + self.w1)*math.sin(self.a0))
        acceleration0_dividend_2 = (self.w1 * self.g * math.sin(self.a0 - 2 * self.a1))
        acceleration0_dividend_3 = (2 * math.sin(self.a0 - self.a1) * self.w1 * ((self.velocity1**2)*self.l1 + (self.velocity0**2) * self.l0 * math.cos(self.a0 - self.a1)))

        acceleration0_divisor = (self.l0*(2*self.w0 + self.w1 - self.w1*math.cos(2*self.a0 - 2*self.a1)))

        self.acceleration0 = (acceleration0_dividend_1 - acceleration0_dividend_2 - acceleration0_dividend_3) / (acceleration0_divisor)



        # Update variables.
        self.velocity1 += self.acceleration1 * d_t # Update velocity.
        # Update angle with angular velocity.
        self.a1 += self.velocity1 * d_t

        # Update variables.
        self.velocity0 += self.acceleration0 * d_t # Update velocity.
        # Update angle with angular velocity.
        self.a0 += self.velocity0 * d_t


        return # Just a stub for now.

```

## Stuff for the future.

Ok, so I think that is it. I think that I am gonna make an n-pendulum system etc. or with damping etc, but I am going to implement those later on.






