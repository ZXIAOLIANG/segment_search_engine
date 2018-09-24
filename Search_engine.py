class Bloomfilter(object):
    def __init__(self, size):
        self.values = [False]*size
        self.size = size

    def hash_value(self, value):
        return hash(value)%self.size

    def add_value(self, value):
        h = self.hash_value(value)
        self.values[h] = True

    def might_contain(self, value):
        h = self.hash_value(value)
        return self.values[h]

    def print_contents(self):
        #for debug purpose
        print self.values

def major_segments(s):
    '''
    Perform major segmenting on a string.  Split the string by all of the major
    breaks, and return the set of everything found.  The breaks in this implementation
    are single characters, but in Splunk proper they can be multiple characters.
    A set is used because ordering doesn't matter, and duplicates are bad.
    '''
    mahor_breaks = ' '
    last = -1
    results = set()

    for idx, ch in enumerate(s):
        if ch in mahor_breaks:
            segment = s[last+1:idx]
            results.add(segment)

            last = idx

    segment = s[last+1:]
    results.add(segment)
    return results

def minor_segments(s):
    '''
    Perform minor segmenting on a string.  This is like major
    segmenting, except it also captures from the start of the
    input to each break.
    '''
    minor_breaks = '_.'
    last = -1
    results = set()

    for idx, ch in enumerate(s):
        if ch in minor_breaks:
            segment = s[last+1:idx]
            results.add(segment)

            segment = s[:idx]
            results.add(segment)

            last = idx

    segment = s[last+1:]
    results.add(segment)
    results.add(s)

    return results
    
def segments(event):
    '''Simple wrapper around major_segments / minor_segments'''
    results = set()
    for major in major_segments(event):
        for minor in minor_segments(major):
            results.add(minor)
    
    return results

class Splunk(object):
    def __init__(self):
        self.bf = Bloomfilter(64)
        self.terms = {}
        self.events = []
    
    def add_event(self, event):
        #generate a unique event id and save it
        event_id = len(self.events)
        self.events.append(event)

        for term in segments(event):
            self.bf.add_value(term)

            if(term not in self.terms):
                self.terms[term] = set()
            self.terms[term].add(event_id)
    
    def search(self, term):
        '''Search for a single term, and yield all the events that contain it'''
        if not self.bf.might_contain(term):
            return
        if term not in self.terms:
            return
        for event_id in sorted(self.terms[term]):
            yield self.events[event_id]
        




if __name__== "__main__":
    '''
    bf = Bloomfilter(10)
    bf.add_value('dog')
    bf.add_value('fish')
    bf.add_value('cat')
    bf.print_contents()

    bf.add_value('bird')
    bf.print_contents()

    for term in ['dog', 'fish', 'cat', 'bird', 'duck', 'emu']:
         print '{}: {} {}'.format(term, bf.hash_value(term), bf.might_contain(term))
    '''
    '''
    for term in segments('src_ip = 1.2.3.4'):
        print term
    '''
    s = Splunk()
    s.add_event('src_ip = 1.2.3.4')
    s.add_event('src_ip = 5.6.7.8')
    s.add_event('dst_ip = 1.2.3.4')
 
    for event in s.search('1.2.3.4'):
        print event
    print '-'
    for event in s.search('src_ip'):
        print event
    print '-'
    for event in s.search('ip'):
        print event
    
