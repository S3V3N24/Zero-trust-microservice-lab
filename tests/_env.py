"""Imported first by every test: puts the project on the path and picks test-only ports and a certificate lifetime short enough to observe rotation."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('ZT_PORT_OFFSET', '32000')
os.environ.setdefault('ZT_SVID_TTL', '20')
