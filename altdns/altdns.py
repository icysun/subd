#!/usr/bin/env python
# released at BSides Canberra by @infosec_au and @nnwakelam
# <3 silvio

import argparse
import threading
import time
import datetime
from threading import Lock
from Queue import Queue as Queue

import tldextract
from tldextract.tldextract import LOG
import logging
from termcolor import colored
import dns.resolver
import re
import os

logging.basicConfig(level=logging.CRITICAL)

def get_alteration_words(wordlist_fname):
    with open(wordlist_fname, "r") as f:
        return f.readlines()

# will write to the file if the check returns true
def write_domain(wp, full_url):
    wp.write(full_url)

# function inserts words at every index of the subdomain
def insert_all_indexes(input_file, output_file_tmp, alteration_words):
    with open(input_file, "r") as fp:
        with open(output_file_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index in range(0, len(current_sub)):
                        current_sub.insert(index, word.strip())
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if actual_sub[-1:] is not ".":
                            write_domain(wp, full_url)
                        current_sub.pop(index)
                    current_sub.append(word.strip())
                    actual_sub = ".".join(current_sub)
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    if len(current_sub[0]) > 0:
                      write_domain(wp, full_url)
                    current_sub.pop()

# adds word-NUM and wordNUM to each subdomain at each unique position
def insert_number_suffix_subdomains(input_file, output_file_tmp, alternation_words):
    with open(input_file, "r") as fp:
        with open(output_file_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in range(0, 10):
                    for index, value in enumerate(current_sub):
                        #add word-NUM
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + "-" + str(word)
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub

                        #add wordNUM
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + str(word)
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub

# adds word- and -word to each subdomain at each unique position
def insert_dash_subdomains(input_file, output_file_tmp, alteration_words):
    with open(input_file, "r") as fp:
        with open(output_file_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index, value in enumerate(current_sub):
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[
                            index] + "-" + word.strip()
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if len(current_sub[0]) > 0 and actual_sub[:1] is not "-":
                            write_domain(wp, full_url)
                        current_sub[index] = original_sub
                        # second dash alteration
                        current_sub[index] = word.strip() + "-" + \
                            current_sub[index]
                        actual_sub = ".".join(current_sub)
                        # save second full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if actual_sub[-1:] is not "-":
                            write_domain(wp, full_url)
                        current_sub[index] = original_sub

# adds prefix and suffix word to each subdomain
def join_words_subdomains(input_file, output_file_tmp, alteration_words):
    with open(input_file, "r") as fp:
        with open(output_file_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index, value in enumerate(current_sub):
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + word.strip()
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub
                        # second dash alteration
                        current_sub[index] = word.strip() + current_sub[index]
                        actual_sub = ".".join(current_sub)
                        # save second full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(wp, full_url)
                        current_sub[index] = original_sub


def get_cname(q, target, resolved_out):
    global progress
    global lock
    global starttime
    global found
    global resolverName
    lock.acquire()
    progress += 1
    lock.release()
    if progress % 500 == 0:
        lock.acquire()
        left = linecount-progress
        secondspassed = (int(time.time())-starttime)+1
        amountpersecond = progress / secondspassed
        lock.release()
        timeleft = str(datetime.timedelta(seconds=int(left/amountpersecond)))
        print(
            colored("[*] {0}/{1} completed, approx {2} left".format(progress, linecount, timeleft),
                    "blue"))
    final_hostname = target
    result = list()
    result.append(target)
    resolver = dns.resolver.Resolver()
    if(resolverName is not None): #if a DNS server has been manually specified
        resolver.nameservers = [resolverName]
    try:
      for rdata in resolver.query(final_hostname, 'CNAME'):
        result.append(rdata.target)
    except:
        pass
    if len(result) is 1:
      try:
        A = resolver.query(final_hostname, "A")
        if len(A) > 0:
          result = list()
          result.append(final_hostname)
          result.append(str(A[0]))
      except:
        pass
    if len(result) > 1: #will always have 1 item (target)
        if str(result[1]) in found:
            if found[str(result[1])] > 3:
                return
            else:
                found[str(result[1])] = found[str(result[1])] + 1
        else:
            found[str(result[1])] = 1
        resolved_out.write(str(result[0]) + ":" + str(result[1]) + "\n")
        resolved_out.flush()
        ext = tldextract.extract(str(result[1]))
        if ext.domain == "amazonaws":
            try:
                for rdata in resolver.query(result[1], 'CNAME'):
                    result.append(rdata.target)
            except:
                pass
        print(
            colored(
                result[0],
                "red") +
            " : " +
            colored(
                result[1],
                "green"))
        if len(result) > 2 and result[2]:
            print(
                colored(
                    result[0],
                    "red") +
                " : " +
                colored(
                    result[1],
                    "green") +
                ": " +
                colored(
                    result[2],
                    "blue"))
    q.put(result)

def remove_existing(input_file, output_file_tmp, output_file):
  with open(input_file) as b:
    blines = set(b)
  with open(output_file_tmp) as a:
    with open(output_file, 'w') as result:
      for line in a:
        if line not in blines:
          result.write(line)
  os.remove(output_file_tmp)

def get_line_count(filename):
    with open(filename, "r") as lc:
        linecount = sum(1 for _ in lc)
    return linecount


def main(input_file, output_file, threads, save):
    q = Queue()
    resolve = True
    wordlist = 'altdns/words.txt'
    resolved_out = open(save, "a")

    alteration_words = get_alteration_words(wordlist)

    # if we should remove existing, save the output to a temporary file
    output_file_tmp = output_file + '.tmp'

    # wipe the output before, so we fresh alternated data
    open(output_file_tmp, 'w').close()

    insert_all_indexes(input_file, output_file_tmp, alteration_words)
    insert_dash_subdomains(input_file, output_file_tmp, alteration_words)
    join_words_subdomains(input_file, output_file_tmp, alteration_words)

    threadhandler = []

    # Removes already existing + dupes from output
    remove_existing(input_file, output_file_tmp, output_file)

    if resolve:
        global progress
        global linecount
        global lock
        global starttime
        global found
        global resolverName       
        lock = Lock()
        found = {}
        progress = 0
        starttime = int(time.time())
        linecount = get_line_count(output_file)
        resolverName = None
        with open(output_file, "r") as fp:
            for i in fp:
                if threads:
                    if len(threadhandler) > int(threads):
                        #Wait until there's only 10 active threads
                        while len(threadhandler) > 10:
                           threadhandler.pop().join()
                try:
                    t = threading.Thread(
                        target=get_cname, args=(
                            q, i.strip(), resolved_out))
                    t.daemon = True
                    threadhandler.append(t)
                    t.start()
                except Exception as error:
                    print("error:"),(error)
            #Wait for threads
            while len(threadhandler) > 0:
               threadhandler.pop().join()
               
        timetaken = str(datetime.timedelta(seconds=(int(time.time())-starttime)))
        print(
            colored("[*] Completed in {0}".format(timetaken),
                    "blue"))

