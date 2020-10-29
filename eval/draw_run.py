import argparse
import os
from collections import namedtuple

import pandas
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure

FigureParameter = namedtuple('FigureParameter', ['tasks',
                                                 'title',
                                                 'filename',
                                                 'use_combined'
                                                 ]
                             )


def plot_bar(df, fig_params: FigureParameter):
    f, ax = plt.subplots()

    t_data = df.loc[df.task.isin(fig_params.tasks)]

    if len(t_data) == 0:
        print("No data for {}".format(fig_params.tasks))
        return

    # plot = sns.barplot(data=t_data, x='combined', y='time', ax=ax, color='#1979a9')
    x_data = t_data.combined if fig_params.use_combined else t_data.parameters
    plot = ax.bar(x=x_data, height=t_data.time, color='#1979a9')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.spines['bottom'].set_color('#DDDDDD')

    bar_color = plot[0].get_facecolor()

    # Add text annotations to the top of the bars.
    # Note, you'll have to adjust this slightly (the 0.3)
    # with different data.
    for bar in plot:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.3,
            round(bar.get_height(), 1),
            horizontalalignment='center',
            color=bar_color,
            weight='bold'
        )

    ax.tick_params(axis='x', rotation=90)

    ax.set_xlabel('Operation', labelpad=15, color='#333333')
    ax.set_ylabel('Time', labelpad=15, color='#333333')
    ax.set_title(fig_params.title, pad=15, color='#333333', weight='bold')

    f.tight_layout()
    print("Saving {}".format(fig_params.filename))
    f.savefig(fig_params.filename)


def main():
    parser = argparse.ArgumentParser(description='draw a performance run')
    parser.add_argument('path', type=str, help='the file path for the performance evaluation output file')
    args = parser.parse_args()
    filepath = args.path

    df = pandas.read_csv(filepath, dtype={'parameters': str}, engine='c')
    df.parameters = df.parameters.fillna('')
    df["combined"] = df["task"].astype(str) + df["parameters"]

    print(df)

    # make dir for figures
    dirpath = filepath[:-4]
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)

    def imgpath(imagefilename):
        return os.path.join(dirpath, imagefilename)

    # single figures

    dkg_task = ["DKG", "CKG"]
    decrypt_task = ["DecryptCombine"]
    diverse_tasks = [
        "ReEncrypt",
        "PartialDecryption",
        "PartialReEncryptionKey",
        "ReEncryptionKeyCombination",
    ]

    figures = [
        # FigureParameter(dkg_task, "Distributed key generation", imgpath("dkg.png"), False),
        # FigureParameter(decrypt_task, "Decryption", imgpath("dec.png"), False),
        FigureParameter(diverse_tasks, "Remaining operations", imgpath("divers.png"), True),
    ]

    """
    performed on "daily business" or multiple times:
    - encryption: just depends on message size (slightly), not on AS
    - re-encryption: does not depend on msg size or AS

    performed on a one-by-one basis:
    - partial decryption: does not depend on msg size or AS 
    - decrypt (combine): does depend on AS (huge impact) and msg size (low impact)
    
    performed once in a while:
    - dkg: huge AS impact
    - ckg: AS impact
    - prek: no AS dependency
    - rekc: irrelevant AS impact
    
    figures:
    - enc: msg size
    - ckg (1), dkg(1), dec(1000): AS impact
    
    - diverse: 
        - partial decryption: ONE
        - prek: ONE
        - rekc: ONE 
        - re-encrypt (relevant)
        
    ALTERNATIVE just relevant:
    - dkg: AS (just one run?), maybe include ckg
    - enc, re-encrypt
    missing: ckg(?), dec, pdec, prek, rekc
    """

    # sns.set_style('whitegrid')

    # f, ax = plt.subplots(2, 2)  # , sharey=True)
    # subplot(diverse_tasks, ax[0][0])
    # subplot(dkg_task, ax[1][0])
    # subplot(decrypt_task, ax[0][1])
    # subplot(encrypt_task, ax[1][1])
    # f.tight_layout()
    # # plt.show()
    # f.savefig("test.png")

    for fig_params in figures:
        plot_bar(df, fig_params)

    f = draw_encryption(df)
    print("Saving {}".format(imgpath("enc_line.png")))
    f.savefig(imgpath("enc_line.png"))

    f = draw_dkg_ckg_dec(df)
    print("Saving {}".format(imgpath("dkg_ckg_dec.png")))
    f.savefig(imgpath("dkg_ckg_dec.png"))


def draw_encryption(df) -> Figure:
    res = plt.subplots()
    f = res[0]
    ax: Axes = res[1]

    t_data = df.loc[df.task == 'Encrypt']
    t_data.parameters = t_data.parameters.astype(int)
    plot = ax.plot(t_data.parameters, t_data.time, color='#1979a9')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#DDDDDD')
    ax.spines['bottom'].set_color('#DDDDDD')

    ax.grid(axis='y', color="#DDDDDD")

    ax.tick_params(axis='both',  color="#DDDDDD") # rotation=45,
    ax.ticklabel_format(style='plain')
    ax.set_ybound(lower=0, upper=ax.get_ybound()[1])
    ax.set_xbound(lower=0, upper=ax.get_xbound()[1])

    ax.set_xlabel('plaintext length [byte]', labelpad=15, color='#333333')
    ax.set_ylabel('time [s]', labelpad=15, color='#333333')
    # ax.set_title("Encryption time for different messages sizes", pad=15, color='#333333', weight='bold')

    f.tight_layout()

    return f


def draw_dkg_ckg_dec(df) -> Figure:
    f, ax = plt.subplots()
    tasks = ["DKG", "CKG", "DecryptCombine"]
    dkg_data = df.loc[df.task == 'DKG']
    ckg_data = df.loc[df.task == 'CKG']
    dec_data = df.loc[df.task == 'DecryptCombine']

    x = np.arange(len(dkg_data))
    width = 0.2

    bar_dkg = ax.bar(x, dkg_data.time, width, label="DKG")
    bar_ckg = ax.bar(x - 1.2 * width, ckg_data.time, width, label="CKG")
    bar_dec = ax.bar(x + 1.2 * width, dec_data.time, width, label="DEC")

    # annotate bars with their respective values
    def autolabel(rects):
        """Attach a text label above each bar in *rects*, displaying its height."""
        bar_color = rects[0].get_facecolor()

        for rect in rects:
            height = rect.get_height()
            ax.annotate('{:0.3f}'.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        rotation=90,
                        ha='center',
                        va='bottom',
                        color=bar_color)

    autolabel(bar_dkg)
    autolabel(bar_ckg)
    autolabel(bar_dec)

    # set graph "borders"
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.spines['bottom'].set_color('#DDDDDD')

    # include grid lines behind bars
    ax.set_axisbelow(True)
    ax.grid(axis='y', color="#DDDDDD")

    # ticks and labels
    ax.tick_params(axis='x', rotation=90)
    ax.tick_params(axis='both', color="#DDDDDD")
    ax.set_xticks(x)
    ax.set_xticklabels(dkg_data.parameters)

    # axis labels and title
    ax.set_xlabel('used (t,n)-scheme', labelpad=15, color='#333333')
    ax.set_ylabel('time [s]', labelpad=15, color='#333333')
    ax.set_title("TITLE", pad=15, color='#333333', weight='bold')

    # insert legend
    ax.legend()

    f.tight_layout()

    return f


if __name__ == '__main__':
    main()
