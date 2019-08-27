#!/usr/bin python3
# Usage: python3 gvfile2csv.py <gvfile> [<csvfile>]
# csv file can open with Microsoft Excel
import sys
import os
import csv

headers = [
        "exec_seed",
        "acess_peripheral",
        "exec_time",
        "exec_cnt",
        "trigger_new_BB_To_BB",
        "trigger_new_Peripheral_To_Peripheral",
        "unique PP_To_PP",
        "unique BB_To_BB",
        "Total_Path",
        "Total_Events",
        "Total_Single_Exec_Time",
        "Total_Exec_Time",
        "Coverage of BB_To_BB"
        ]

def gv2csv(gvfilename, csvfilename):
    with open(gvfilename, mode='r', encoding="utf-8") as fr:
        gvlist = fr.readlines()
    gvlist = [gv.strip() for gv in gvlist]
    
    gvdict = {}
    gvdictlist = []
    for gv in gvlist:
        if ": " in gv:
            kv = gv.split(": ")
            gvdict[kv[0]] = eval(kv[1])
        elif gvdict != {}:
            gvdictlist.append(gvdict)
            gvdict = {}

    timesort = sorted(gvdictlist, key=lambda gv: gv["Total_Exec_Time"])
    eventsort = sorted(gvdictlist, key=lambda gv: gv["Total_Events"])
    if timesort != eventsort:
        print("[-] Some error!")
        print("    Order in gvfile is incorrect.")
        return

    with open(csvfilename, mode='w', encoding="utf-8", newline="") as fw:
        f_csv = csv.writer(fw)
        f_csv.writerow([" "] + headers)
        for i, gvdict in enumerate(timesort):
            csvrow = [i, ]
            for k in headers:
                csvrow.append(gvdict.get(k, '--'))
            f_csv.writerow(csvrow)


if __name__ == "__main__":
    if 2 <= len(sys.argv) <= 3:
        gvfilename = sys.argv[1]
        if not os.path.exists(gvfilename):
            print("[-] gvfilename is no existed!")
        if len(sys.argv) == 2:
            csvfilename = gvfilename.replace(".txt", ".csv")
        else:
            csvfilename = sys.argv[2]
        gv2csv(gvfilename, csvfilename)
    else:
        print("Usage: python3 gvfile2csv.py <gvfile> [<csvfile>]")