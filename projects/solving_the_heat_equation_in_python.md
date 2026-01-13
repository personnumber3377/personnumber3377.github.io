
# Solving the heat equation in python

Hi! Ok, so I was inspired by this: https://medium.com/@matiasortizdiez/beginners-introduction-to-natural-simulation-in-python-i-solving-the-heat-equation-bf0ae5d4c37f and I decided to give it a crack.

The article goes into detail about discretization and stuff like that.

The guy goes into the maths and derives a discretized equation for the heat at spot x after n timesteps and it is this:

{% raw %}
```
u(t+dt,x) = k*(dt/(dx**2)*(u(t, x + dx)) - 2 * u(t,x) + u(t, x - dx)) + u(t, x)
```
{% endraw %}

Here is the python code for it:

{% raw %}
```

import numpy
from matplotlib import pyplot

length = 2
k = .466
temp_left = 200
temp_right = 200

total_time = 4

dx = .1
x_vec = numpy.linspace(0, length, int(length/dx))

dt = .0001
t_vec = numpy.linspace(0, total_time, int(total_time/dt))

u = numpy.zeros([len(t_vec), len(x_vec)])

u[:, 0] = temp_left
u[:, -1] = temp_right

for t in range(1, len(t_vec)-1):
    for x in range(1, len(x_vec)-1):
        u[t+1, x] = k * (dt / dx**2) * (u[t, x+1] - 2*u[t, x] +
                                        u[t, x-1]) + u[t, x]

    pyplot.plot(x_vec, u[t], 'black')
    pyplot.pause(.001)
    pyplot.cla()


pyplot.plot(x_vec, u[0])
pyplot.ylabel("Temperature (C˚)")
pyplot.xlabel("Distance Along Rod (m)")
pyplot.show()
```
{% endraw %}














