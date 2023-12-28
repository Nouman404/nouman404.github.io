import qrcode
from PIL import Image

def combine_qr_parts(part_1_path, part_2_path, part_3_path, part_4_path, output_path):
    part_1 = Image.open(part_1_path)
    part_2 = Image.open(part_2_path)
    part_3 = Image.open(part_3_path)
    part_4 = Image.open(part_4_path)

    # Créer une nouvelle image pour combiner les parties
    width = part_2.width + part_3.width
    height = part_2.height + part_4.height
    combined_image = Image.new('RGB', (width, height))

    # Coller les parties dans la nouvelle image
    combined_image.paste(part_1, (0, 0))
    combined_image.paste(part_2, (part_2.width, 0))
    combined_image.paste(part_3, (0, part_2.height))
    combined_image.paste(part_4, (part_2.width, part_2.height))

    # Enregistrer l'image combinée
    combined_image.save(output_path)

    print(f"Image combinée enregistrée à : {output_path}")

# Exemple d'utilisation
combine_qr_parts('1.png','2.png', '3.png', '4.png', 'qr_code_combined.png')

from pyzbar.pyzbar import decode
decodeQR = decode(Image.open('qr_code_combined.png'))
print(decodeQR[0][0].decode())
