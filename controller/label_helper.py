import os

def get_current_label():
    label_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dataset', 'current_label.txt')
    try:
        with open(label_file, 'r') as f:
            return f.read().strip()
    except:
        return 'normal'
