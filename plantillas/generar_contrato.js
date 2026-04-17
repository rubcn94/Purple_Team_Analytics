const { Document, Packer, Paragraph, Table, TableRow, TableCell, TextRun, PageBreak, AlignmentType, BorderStyle, WidthType } = require('docx');
const fs = require('fs');

// Colores corporativos
const PURPLE = 'B3A0FA';
const DARK_PURPLE = '6B3FA0';

// Función para crear título
function crearTitulo(texto) {
  return new Paragraph({
    text: texto,
    spacing: { line: 240, after: 240, before: 240 },
    alignment: AlignmentType.CENTER,
    run: new TextRun({
      font: 'Arial',
      size: 28,
      bold: true,
      color: DARK_PURPLE
    })
  });
}

// Función para crear subtítulo de cláusula
function crearSubtitulo(texto) {
  return new Paragraph({
    text: texto,
    spacing: { line: 240, after: 200, before: 200 },
    alignment: AlignmentType.LEFT,
    run: new TextRun({
      font: 'Arial',
      size: 24,
      bold: true,
      color: DARK_PURPLE
    })
  });
}

// Función para crear párrafo normal
function crearParrafo(texto, opciones = {}) {
  const {
    size = 22,
    bold = false,
    italic = false,
    color = '000000',
    alignment = AlignmentType.JUSTIFIED,
    spacing = 200
  } = opciones;

  return new Paragraph({
    text: texto,
    spacing: { line: spacing, after: 200 },
    alignment: alignment,
    run: new TextRun({
      font: 'Arial',
      size: size,
      bold: bold,
      italic: italic,
      color: color
    })
  });
}

// Crear tabla de servicios (5 filas vacías + total)
function crearTablaServicios() {
  const filas = [
    new TableRow({
      tableHeader: true,
      height: { value: 400, rule: 'exact' },
      children: [
        new TableCell({
          width: { size: 35, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Descripción del Servicio',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        }),
        new TableCell({
          width: { size: 20, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Precio Unitario',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        }),
        new TableCell({
          width: { size: 15, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Cantidad',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        }),
        new TableCell({
          width: { size: 30, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Total',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        })
      ]
    })
  ];

  // Añadir 5 filas vacías
  for (let i = 0; i < 5; i++) {
    filas.push(
      new TableRow({
        height: { value: 600, rule: 'exact' },
        children: [
          new TableCell({
            width: { size: 35, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          }),
          new TableCell({
            width: { size: 20, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          }),
          new TableCell({
            width: { size: 15, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          }),
          new TableCell({
            width: { size: 30, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          })
        ]
      })
    );
  }

  // Fila de TOTAL
  filas.push(
    new TableRow({
      height: { value: 500, rule: 'exact' },
      children: [
        new TableCell({
          columnSpan: 3,
          width: { size: 70, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'TOTAL',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        }),
        new TableCell({
          width: { size: 30, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: '',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        })
      ]
    })
  );

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: filas
  });
}

// Crear tabla para Anexo I (sistemas autorizados)
function crearTablaAnexo() {
  const filas = [
    new TableRow({
      tableHeader: true,
      height: { value: 400, rule: 'atleast' },
      children: [
        new TableCell({
          width: { size: 40, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Sistema / Aplicación',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        }),
        new TableCell({
          width: { size: 30, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Tipo de Auditoría',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        }),
        new TableCell({
          width: { size: 30, type: WidthType.PERCENTAGE },
          shading: { fill: PURPLE, val: 'clear' },
          children: [new Paragraph({
            text: 'Estado',
            run: new TextRun({ bold: true, color: 'FFFFFF', font: 'Arial', size: 20 })
          })]
        })
      ]
    })
  ];

  // 5 filas vacías para el Anexo
  for (let i = 0; i < 5; i++) {
    filas.push(
      new TableRow({
        height: { value: 600, rule: 'exact' },
        children: [
          new TableCell({
            width: { size: 40, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          }),
          new TableCell({
            width: { size: 30, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          }),
          new TableCell({
            width: { size: 30, type: WidthType.PERCENTAGE },
            borders: { all: { style: BorderStyle.SINGLE, size: 6, color: '000000' } },
            children: [new Paragraph({ text: '' })]
          })
        ]
      })
    );
  }

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: filas
  });
}

// Crear el documento
const doc = new Document({
  sections: [
    {
      children: [
        // ENCABEZADO
        new Paragraph({
          text: '',
          spacing: { after: 400 }
        }),

        crearTitulo('CONTRATO DE PRESTACIÓN DE SERVICIOS DE CIBERSEGURIDAD'),

        new Paragraph({
          text: '',
          spacing: { after: 200 }
        }),

        crearParrafo('Número de Contrato: _______________________', {
          alignment: AlignmentType.RIGHT,
          spacing: 200
        }),

        crearParrafo('Fecha: _____________________________', {
          alignment: AlignmentType.RIGHT,
          spacing: 200
        }),

        // PARTES CONTRATANTES
        crearSubtitulo('PARTES CONTRATANTES'),

        crearParrafo('PRIMERA PARTE – PRESTADOR DE SERVICIOS', { bold: true, size: 22 }),

        crearParrafo('Denominación Social: Purple Team Security', { size: 22 }),
        crearParrafo('CIF: _______________________', { size: 22 }),
        crearParrafo('Domicilio: _______________________________________________________', { size: 22 }),
        crearParrafo('Email: _____________________________     Teléfono: _________________', { size: 22 }),

        crearParrafo('SEGUNDA PARTE – CLIENTE', { bold: true, size: 22 }),

        crearParrafo('Nombre/Razón Social: _______________________________________________________', { size: 22 }),
        crearParrafo('NIF/CIF: _______________________', { size: 22 }),
        crearParrafo('Domicilio: _______________________________________________________', { size: 22 }),
        crearParrafo('Email: _____________________________     Teléfono: _________________', { size: 22 }),

        crearParrafo('Ambas partes reconocen su capacidad legal y acuerdan celebrar el presente contrato conforme a las cláusulas que se establecen a continuación.', { spacing: 240 }),

        // CLÁUSULAS
        crearSubtitulo('CLÁUSULAS'),

        // PRIMERA
        crearParrafo('PRIMERA – OBJETO DEL CONTRATO', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('Purple Team Security se compromete a prestar servicios de auditoría de seguridad informática al Cliente, conforme al alcance, características y especificaciones técnicas detalladas en el Anexo I del presente contrato. Dichos servicios incluyen pruebas de penetración, evaluaciones de vulnerabilidades, auditorías de aplicaciones y cualquier otro servicio especificado en el documento de alcance adjunto.'),

        // SEGUNDA
        crearParrafo('SEGUNDA – SERVICIOS INCLUIDOS', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearTablaServicios(),

        new Paragraph({ text: '', spacing: { after: 300 } }),

        // TERCERA
        crearParrafo('TERCERA – PRECIO Y FORMA DE PAGO', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('Precio total del contrato: _________________ € + 21% IVA = _________________ €'),

        crearParrafo('La forma de pago se realizará de la siguiente manera:'),

        crearParrafo('• 50% del total a la firma del contrato'),
        crearParrafo('• 50% del total a la entrega del informe final'),

        crearParrafo('Datos bancarios para el pago:', { bold: true }),

        crearParrafo('IBAN: _________________________________________________________________'),
        crearParrafo('BIC: ___________________________________________________________________'),

        // CUARTA
        crearParrafo('CUARTA – PLAZO DE EJECUCIÓN', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('Fecha de inicio de los servicios: _______________________'),

        crearParrafo('Fecha prevista de entrega del informe: _______________________'),

        crearParrafo('Plazo máximo de ejecución: _________ días hábiles desde la firma del presente contrato. En caso de que Purple Team Security requiera plazo adicional por causa no imputable al prestador, notificará al Cliente con antelación suficiente.'),

        // QUINTA
        crearParrafo('QUINTA – CONFIDENCIALIDAD', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('Purple Team Security se compromete a mantener la máxima confidencialidad respecto a toda la información del Cliente a la que tenga acceso en el desempeño de sus funciones. La información será tratada exclusivamente para los fines del contrato y no será divulgada a terceros sin consentimiento previo y escrito del Cliente. Esta obligación de confidencialidad se mantiene durante tres (3) años después de la finalización del contrato.'),

        // SEXTA
        crearParrafo('SEXTA – LIMITACIÓN DE RESPONSABILIDAD', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('Purple Team Security no será responsable de interrupciones de servicio, caídas de sistemas, pérdida de datos o cualquier otro daño que pudiera derivarse de las pruebas de penetración u otras pruebas técnicas realizadas dentro del alcance autorizado del presente contrato. El Cliente es responsable de tener copias de seguridad de sus datos y sistemas. La responsabilidad máxima de Purple Team Security queda limitada al importe total facturado en el presente contrato.'),

        // SÉPTIMA
        crearParrafo('SÉPTIMA – PROTECCIÓN DE DATOS (RGPD)', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('Ambas partes se comprometen a cumplir con el Reglamento (UE) 2016/679 de Protección de Datos (RGPD) y con la Ley Orgánica 3/2018 de Protección de Datos Personales y garantía de derechos digitales (LOPDGDD). Los datos personales que sean tratados en el curso de la prestación del servicio serán únicamente los estrictamente necesarios para la ejecución del contrato. Purple Team Security actuará como Encargado de Tratamiento respecto a cualquier dato personal del Cliente.'),

        // OCTAVA
        crearParrafo('OCTAVA – PROPIEDAD INTELECTUAL', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('El informe de auditoría de seguridad generado como resultado de los servicios contratados es propiedad intelectual del Cliente una vez que se haya realizado el pago íntegro del precio. Sin embargo, las herramientas, metodologías, plantillas, procesos y cualquier otra propiedad intelectual preexistente o desarrollada por Purple Team Security durante la prestación del servicio permanecen siendo propiedad exclusiva de Purple Team Security. El Cliente no podrá reproducir, modificar, distribuir o comercializar el informe sin consentimiento escrito de Purple Team Security.'),

        // NOVENA
        crearParrafo('NOVENA – RESOLUCIÓN DEL CONTRATO', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('El presente contrato podrá ser resuelto por incumplimiento de cualquiera de las partes, previo preaviso escrito con un plazo de quince (15) días hábiles para subsanar el incumplimiento. En caso de resolución por incumplimiento del Cliente (especialmente en materia de pago), el Cliente abonará íntegramente los servicios ya prestados por Purple Team Security hasta el momento de la resolución.'),

        // DÉCIMA
        crearParrafo('DÉCIMA – LEY APLICABLE Y JURISDICCIÓN', { bold: true, color: DARK_PURPLE, size: 22 }),

        crearParrafo('El presente contrato se rige por la legislación española, concretamente por el Código Civil, la Ley de Servicios de la Sociedad de la Información y de Comercio Electrónico, y la normativa en materia de Ciberseguridad. Para cualquier controversia derivada de este contrato, las partes se someten a los juzgados y tribunales competentes de [CIUDAD], renunciando a cualquier otro fuero que pudiera corresponderles.'),

        // FIRMAS
        new Paragraph({
          text: 'FIRMAS DE LAS PARTES',
          spacing: { before: 400, after: 300 },
          alignment: AlignmentType.CENTER,
          run: new TextRun({ font: 'Arial', size: 22, bold: true, color: DARK_PURPLE })
        }),

        new Paragraph({
          text: '',
          spacing: { after: 300 }
        }),

        new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          rows: [
            new TableRow({
              height: { value: 600, rule: 'exact' },
              children: [
                new TableCell({
                  width: { size: 50, type: WidthType.PERCENTAGE },
                  borders: { all: { style: BorderStyle.NONE } },
                  children: [
                    new Paragraph({
                      text: 'PURPLE TEAM SECURITY',
                      spacing: { after: 300 },
                      alignment: AlignmentType.CENTER,
                      run: new TextRun({ font: 'Arial', size: 20, bold: true })
                    }),
                    new Paragraph({
                      text: '',
                      spacing: { after: 300 }
                    }),
                    new Paragraph({
                      text: '',
                      spacing: { after: 100 }
                    }),
                    new Paragraph({
                      text: 'Firma y sello',
                      alignment: AlignmentType.CENTER,
                      run: new TextRun({ font: 'Arial', size: 20, italic: true })
                    }),
                    new Paragraph({
                      text: 'DNI/CIF: _____________________________',
                      alignment: AlignmentType.CENTER,
                      spacing: { after: 100 },
                      run: new TextRun({ font: 'Arial', size: 20 })
                    }),
                    new Paragraph({
                      text: 'Fecha: _____________________________',
                      alignment: AlignmentType.CENTER,
                      run: new TextRun({ font: 'Arial', size: 20 })
                    })
                  ]
                }),
                new TableCell({
                  width: { size: 50, type: WidthType.PERCENTAGE },
                  borders: { all: { style: BorderStyle.NONE } },
                  children: [
                    new Paragraph({
                      text: 'CLIENTE',
                      spacing: { after: 300 },
                      alignment: AlignmentType.CENTER,
                      run: new TextRun({ font: 'Arial', size: 20, bold: true })
                    }),
                    new Paragraph({
                      text: '',
                      spacing: { after: 300 }
                    }),
                    new Paragraph({
                      text: '',
                      spacing: { after: 100 }
                    }),
                    new Paragraph({
                      text: 'Firma y sello',
                      alignment: AlignmentType.CENTER,
                      run: new TextRun({ font: 'Arial', size: 20, italic: true })
                    }),
                    new Paragraph({
                      text: 'DNI/CIF: _____________________________',
                      alignment: AlignmentType.CENTER,
                      spacing: { after: 100 },
                      run: new TextRun({ font: 'Arial', size: 20 })
                    }),
                    new Paragraph({
                      text: 'Fecha: _____________________________',
                      alignment: AlignmentType.CENTER,
                      run: new TextRun({ font: 'Arial', size: 20 })
                    })
                  ]
                })
              ]
            })
          ]
        }),

        // SALTO DE PÁGINA PARA ANEXO
        new PageBreak(),

        // ANEXO I
        new Paragraph({
          text: 'ANEXO I – ALCANCE DETALLADO DE LA AUDITORÍA',
          spacing: { before: 200, after: 300 },
          alignment: AlignmentType.CENTER,
          run: new TextRun({ font: 'Arial', size: 28, bold: true, color: DARK_PURPLE })
        }),

        new Paragraph({
          text: 'En el presente Anexo se especifican los sistemas, aplicaciones y componentes informáticos que están incluidos dentro del alcance de la auditoría de seguridad a realizar por Purple Team Security.',
          spacing: { after: 300 },
          alignment: AlignmentType.JUSTIFIED,
          run: new TextRun({ font: 'Arial', size: 22 })
        }),

        crearTablaAnexo(),

        new Paragraph({
          text: '',
          spacing: { after: 300 }
        }),

        new Paragraph({
          text: 'Notas y aclaraciones:',
          spacing: { before: 200, after: 100 },
          run: new TextRun({ font: 'Arial', size: 22, bold: true })
        }),

        crearParrafo('_______________________________________________________________________'),
        crearParrafo('_______________________________________________________________________'),
        crearParrafo('_______________________________________________________________________'),

        new Paragraph({
          text: 'El presente Anexo I es parte integral del Contrato de Prestación de Servicios de Ciberseguridad celebrado entre Purple Team Security y el Cliente.',
          spacing: { before: 200, after: 100 },
          alignment: AlignmentType.JUSTIFIED,
          run: new TextRun({ font: 'Arial', size: 22, italic: true })
        })
      ]
    }
  ]
});

// Generar el documento
Packer.toBuffer(doc).then(buffer => {
  const filePath = '/sessions/amazing-laughing-wozniak/mnt/Termux_Purple_Team/plantillas/contrato_servicios.docx';
  fs.writeFileSync(filePath, buffer);
  console.log('Documento creado exitosamente en: ' + filePath);
});
