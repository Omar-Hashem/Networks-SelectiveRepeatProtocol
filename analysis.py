import matplotlib.pyplot as plt
from multiprocessing import Pool

def plot_congestion_control(analysis):

    p = Pool(5)
    p.map(_plot_congestion_control, [analysis])

def _plot_congestion_control(analysis):
    analysis.sort(key=lambda x: x[0])

    x = [xx for xx, yy in analysis]
    y = [yy for xx, yy in analysis]

    # Plot the points using matplotlib
    plt.plot(x, y)
    plt.xlabel('Packets Send Base')
    plt.ylabel('Window Size')
    plt.title('Congestion Control')

    plt.show()
