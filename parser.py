# parser.py
import cv2
import numpy as np
import pytesseract
import re
from dateutil import parser as dateparser

# Simple preprocessing: grayscale -> denoise -> adaptive threshold -> deskew
def preprocess_image_cv(image):
    # image: BGR numpy array
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    gray = cv2.medianBlur(gray, 3)
    th = cv2.adaptiveThreshold(gray,255,cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                               cv2.THRESH_BINARY,31,2)
    # deskew
    coords = np.column_stack(np.where(th > 0))
    if coords.size:
        rect = cv2.minAreaRect(coords)
        angle = rect[-1]
        if angle < -45:
            angle = -(90 + angle)
        else:
            angle = -angle
        (h, w) = th.shape
        M = cv2.getRotationMatrix2D((w//2, h//2), angle, 1.0)
        th = cv2.warpAffine(th, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    return th

def ocr_image(image):
    # Provide config: OCR Engine Mode 3 (default), page segmentation mode 6 (assume a block of text)
    custom_config = r'--oem 3 --psm 6'
    text = pytesseract.image_to_string(image, config=custom_config)
    return text

def extract_total(text):
    # Look for words like total, amount, grand total, balance
    pattern = r'((?:grand\s+total|total\s+due|total|amount\s+due|amount|balance)[\s:\-]*₹?\$?\s*[\d,]+(?:\.\d{1,2})?)'
    matches = re.findall(pattern, text, flags=re.IGNORECASE)
    if matches:
        last = matches[-1]
        num = re.search(r'(\d[\d,]*\.?\d{0,2})', last)
        if num:
            try:
                return float(num.group(1).replace(',',''))
            except:
                pass
    # fallback: find all monetary patterns and pick max
    amounts = re.findall(r'\d{1,3}(?:[,\d]{0,})\.\d{2}', text)
    clean_amounts = []
    for a in amounts:
        try:
            clean_amounts.append(float(a.replace(',','')))
        except:
            pass
    if clean_amounts:
        return max(clean_amounts)
    # no amount found
    return None

def extract_date(text):
    # common date formats
    date_candidates = re.findall(r'(\d{1,2}[\/\-\.\s]\d{1,2}[\/\-\.\s]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}|[A-Za-z]{3,9}\s+\d{1,2},?\s*\d{0,4})', text)
    for d in date_candidates:
        try:
            parsed = dateparser.parse(d, fuzzy=True)
            return parsed.date().isoformat()
        except:
            continue
    return None

def extract_invoice_number(text):
    m = re.search(r'(invoice|inv|bill)\s*(?:no|#|number)?\s*[:\-]?\s*([A-Za-z0-9\-\/]+)', text, flags=re.IGNORECASE)
    if m:
        return m.group(2)
    # fallback generic No. patterns
    m2 = re.search(r'No\.?\s*[:\-]?\s*([A-Za-z0-9\-\/]+)', text)
    if m2:
        return m2.group(1)
    return None

def extract_vendor(text):
    # naive: vendor is likely in the first few non-empty lines
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return None
    # skip lines that look like addresses or "invoice"
    for i, line in enumerate(lines[:6]):
        low = line.lower()
        if any(k in low for k in ['invoice', 'bill to', 'date', 'no', 'tax', 'gst', 'total']):
            continue
        # return the first "clean" line
        return line
    return lines[0]

def process_invoice_image_bgr(bgr_img):
    """
    Returns dict: vendor, invoice_no, date, total, raw_text
    """
    pre = preprocess_image_cv(bgr_img)
    text = ocr_image(pre)
    vendor = extract_vendor(text)
    inv_no = extract_invoice_number(text)
    inv_date = extract_date(text)
    total = extract_total(text)

    # category via rule-based mapper
    category = rule_based_category(text)

    return {
        'vendor': vendor,
        'invoice_no': inv_no,
        'date': inv_date,
        'total': total,
        'category': category,
        'raw_text': text
    }

def rule_based_category(text):
    """
    Simple keyword-based mapping. Extend this with ML/classifier later.
    """
    text_low = (text or '').lower()
    mapping = {
        'travel': ['uber','ola','airlines','flight','taxi','indigo','spicejet','vistara','bus','train','booking.com'],
        'food': ['restaurant','cafe','starbucks','food','zomato','swiggy','dominos','subway','mcdonald'],
        'office': ['office','stationery','pen','paper','staples','notebook','amazon','flipkart','office supplies'],
        'software': ['microsoft','adobe','office 365','github','aws','google cloud','gcp','digitalocean'],
        'utilities': ['electricity','water bill','gas','utility'],
        'health': ['clinic','hospital','pharmacy','medic','lab'],
        'electronics': ['electronic','mobile','laptop','charger','lenovo','dell','hp','samsung']
    }
    # score mapping
    scores = {}
    for cat, keywords in mapping.items():
        for kw in keywords:
            if kw in text_low:
                scores[cat] = scores.get(cat, 0) + 1
    if not scores:
        return 'Other'
    # highest scoring category
    return max(scores.items(), key=lambda x: x[1])[0]
