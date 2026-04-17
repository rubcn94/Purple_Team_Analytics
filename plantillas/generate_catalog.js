const { Document, Packer, Paragraph, Table, TableCell, TableRow, TextRun, ShadingType, AlignmentType, VerticalAlign } = require('docx');
const fs = require('fs');
const path = require('path');

// Color corporativo
const PURPLE = '6B3FA0';
const LIGHT_BG = 'F3EEF9';

// Crear el documento
const doc = new Document({
  sections: [
    {
      properties: {
        page: {
          pageNumberStart: 1,
        },
      },
      children: [
        // HEADER - TÍTULO PRINCIPAL
        new Paragraph({
          text: 'CATÁLOGO DE SERVICIOS',
          spacing: {
            before: 400,
            after: 100,
          },
          alignment: AlignmentType.CENTER,
          runs: [
            new TextRun({
              text: 'CATÁLOGO DE SERVICIOS',
              bold: true,
              size: 32,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        // LOGO / EMPRESA
        new Paragraph({
          text: 'PURPLE TEAM SECURITY',
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
          runs: [
            new TextRun({
              text: 'PURPLE TEAM SECURITY',
              bold: true,
              size: 28,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        // SUBTÍTULO
        new Paragraph({
          text: 'Auditoría de seguridad y cumplimiento RGPD para empresas',
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: 'Auditoría de seguridad y cumplimiento RGPD para empresas',
              italics: true,
              size: 22,
              color: '666666',
              font: 'Arial',
            }),
          ],
        }),

        // SEPARADOR
        new Paragraph({
          text: '━'.repeat(60),
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: '━'.repeat(60),
              color: PURPLE,
              size: 18,
            }),
          ],
        }),

        // SECCIÓN 1 - DIAGNÓSTICO GRATUITO
        new Paragraph({
          text: 'SECCIÓN 1 — DIAGNÓSTICO GRATUITO',
          spacing: { before: 200, after: 200 },
          runs: [
            new TextRun({
              text: 'SECCIÓN 1 — DIAGNÓSTICO GRATUITO',
              bold: true,
              size: 24,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Análisis express de 10 minutos sin coste ni compromiso. Comprobamos tu web, conexión y presencia online e identificamos los principales riesgos de cumplimiento legal.',
          spacing: { after: 200 },
          runs: [
            new TextRun({
              text: 'Análisis express de 10 minutos sin coste ni compromiso. Comprobamos tu web, conexión y presencia online e identificamos los principales riesgos de cumplimiento legal.',
              italics: true,
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Incluye:',
          spacing: { after: 100 },
          runs: [
            new TextRun({
              text: 'Incluye:',
              bold: true,
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• HTTPS/SSL',
          spacing: { after: 80 },
          runs: [
            new TextRun({
              text: '• HTTPS/SSL',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Política de privacidad',
          spacing: { after: 80 },
          runs: [
            new TextRun({
              text: '• Política de privacidad',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Aviso de cookies',
          spacing: { after: 80 },
          runs: [
            new TextRun({
              text: '• Aviso de cookies',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Headers de seguridad',
          spacing: { after: 300 },
          runs: [
            new TextRun({
              text: '• Headers de seguridad',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // Precio y ideal para
        new Paragraph({
          text: 'Precio: ',
          spacing: { after: 100 },
          runs: [
            new TextRun({
              text: 'Precio: ',
              bold: true,
              size: 20,
              font: 'Arial',
            }),
            new TextRun({
              text: 'GRATUITO',
              bold: true,
              size: 20,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Ideal para: Primera toma de contacto.',
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: 'Ideal para: Primera toma de contacto.',
              italics: true,
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // SEPARADOR
        new Paragraph({
          text: '━'.repeat(60),
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: '━'.repeat(60),
              color: PURPLE,
              size: 18,
            }),
          ],
        }),

        // SECCIÓN 2 - PAQUETES DE SERVICIO
        new Paragraph({
          text: 'SECCIÓN 2 — PAQUETES DE SERVICIO',
          spacing: { before: 200, after: 400 },
          runs: [
            new TextRun({
              text: 'SECCIÓN 2 — PAQUETES DE SERVICIO',
              bold: true,
              size: 24,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        // TABLA DE SERVICIOS
        createServicesTable(),

        new Paragraph({
          text: '',
          spacing: { after: 600 },
        }),

        // SEPARADOR
        new Paragraph({
          text: '━'.repeat(60),
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: '━'.repeat(60),
              color: PURPLE,
              size: 18,
            }),
          ],
        }),

        // SECCIÓN 3 - QUÉ INCLUYE EL INFORME
        new Paragraph({
          text: 'SECCIÓN 3 — ¿QUÉ INCLUYE EL INFORME?',
          spacing: { before: 200, after: 300 },
          runs: [
            new TextRun({
              text: 'SECCIÓN 3 — ¿QUÉ INCLUYE EL INFORME?',
              bold: true,
              size: 24,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Resumen ejecutivo no técnico',
          spacing: { after: 150 },
          runs: [
            new TextRun({
              text: '• Resumen ejecutivo no técnico',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Riesgos clasificados por severidad',
          spacing: { after: 150 },
          runs: [
            new TextRun({
              text: '• Riesgos clasificados por severidad',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Impacto legal y económico estimado',
          spacing: { after: 150 },
          runs: [
            new TextRun({
              text: '• Impacto legal y económico estimado',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Plan de remediación con prioridades',
          spacing: { after: 150 },
          runs: [
            new TextRun({
              text: '• Plan de remediación con prioridades',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '• Evidencias de cada hallazgo',
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: '• Evidencias de cada hallazgo',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // SEPARADOR
        new Paragraph({
          text: '━'.repeat(60),
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: '━'.repeat(60),
              color: PURPLE,
              size: 18,
            }),
          ],
        }),

        // SECCIÓN 4 - FAQ
        new Paragraph({
          text: 'SECCIÓN 4 — PREGUNTAS FRECUENTES',
          spacing: { before: 200, after: 400 },
          runs: [
            new TextRun({
              text: 'SECCIÓN 4 — PREGUNTAS FRECUENTES',
              bold: true,
              size: 24,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        // FAQ 1
        new Paragraph({
          text: '¿Cuánto tarda una auditoría?',
          spacing: { before: 200, after: 100 },
          runs: [
            new TextRun({
              text: '¿Cuánto tarda una auditoría?',
              bold: true,
              size: 20,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: '24-72 horas para resultados preliminares, 1 semana para informe completo.',
          spacing: { after: 200 },
          runs: [
            new TextRun({
              text: '24-72 horas para resultados preliminares, 1 semana para informe completo.',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // FAQ 2
        new Paragraph({
          text: '¿Necesito conocimientos técnicos?',
          spacing: { before: 200, after: 100 },
          runs: [
            new TextRun({
              text: '¿Necesito conocimientos técnicos?',
              bold: true,
              size: 20,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'No. Los informes están escritos para propietarios de negocio, con lenguaje claro y accesible.',
          spacing: { after: 200 },
          runs: [
            new TextRun({
              text: 'No. Los informes están escritos para propietarios de negocio, con lenguaje claro y accesible.',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // FAQ 3
        new Paragraph({
          text: '¿Es legal que analicéis mi web?',
          spacing: { before: 200, after: 100 },
          runs: [
            new TextRun({
              text: '¿Es legal que analicéis mi web?',
              bold: true,
              size: 20,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Sí. El análisis externo de webs públicas es completamente legal. Para redes internas firmamos un documento de autorización previo.',
          spacing: { after: 200 },
          runs: [
            new TextRun({
              text: 'Sí. El análisis externo de webs públicas es completamente legal. Para redes internas firmamos un documento de autorización previo.',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // FAQ 4
        new Paragraph({
          text: '¿Qué pasa si encuentran algo grave?',
          spacing: { before: 200, after: 100 },
          runs: [
            new TextRun({
              text: '¿Qué pasa si encuentran algo grave?',
              bold: true,
              size: 20,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Te avisamos de inmediato y priorizamos la solución. Si es urgente, te asistimos ese mismo día.',
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: 'Te avisamos de inmediato y priorizamos la solución. Si es urgente, te asistimos ese mismo día.',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // SEPARADOR
        new Paragraph({
          text: '━'.repeat(60),
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
          runs: [
            new TextRun({
              text: '━'.repeat(60),
              color: PURPLE,
              size: 18,
            }),
          ],
        }),

        // SECCIÓN 5 - CONTACTO
        new Paragraph({
          text: 'SECCIÓN 5 — CONTACTO',
          spacing: { before: 200, after: 400 },
          runs: [
            new TextRun({
              text: 'SECCIÓN 5 — CONTACTO',
              bold: true,
              size: 24,
              color: PURPLE,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Purple Team Security',
          spacing: { after: 200 },
          runs: [
            new TextRun({
              text: 'Purple Team Security',
              bold: true,
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Email: contacto@purpleteam.es',
          spacing: { after: 120 },
          runs: [
            new TextRun({
              text: 'Email: contacto@purpleteam.es',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Teléfono: +34 900 123 456',
          spacing: { after: 120 },
          runs: [
            new TextRun({
              text: 'Teléfono: +34 900 123 456',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        new Paragraph({
          text: 'Web: www.purpleteam.es',
          spacing: { after: 400 },
          runs: [
            new TextRun({
              text: 'Web: www.purpleteam.es',
              size: 20,
              font: 'Arial',
            }),
          ],
        }),

        // Footer
        new Paragraph({
          text: '━'.repeat(60),
          alignment: AlignmentType.CENTER,
          spacing: { before: 600, after: 200 },
          runs: [
            new TextRun({
              text: '━'.repeat(60),
              color: PURPLE,
              size: 18,
            }),
          ],
        }),

        new Paragraph({
          text: 'Purple Team Security | www.purpleteam.es',
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
          runs: [
            new TextRun({
              text: 'Purple Team Security | www.purpleteam.es',
              size: 18,
              color: '999999',
              font: 'Arial',
            }),
          ],
        }),
      ],
    },
  ],
});

// Función para crear la tabla de servicios
function createServicesTable() {
  const services = [
    {
      name: 'BÁSICO — Cumplimiento RGPD Web',
      description: 'Auditoría web completa: SSL/TLS, headers de seguridad, cookies, política de privacidad, formularios, aviso legal. Informe PDF con riesgos y recomendaciones.',
      price: '299 € + IVA',
    },
    {
      name: 'ESTÁNDAR — Auditoría Web Completa',
      description: 'Todo lo del Básico + análisis de subdominios, directorios expuestos, tecnologías vulnerables, correlación de CVEs.',
      price: '599 € + IVA',
    },
    {
      name: 'WIFI — Auditoría de Red Local',
      description: 'Análisis de red WiFi del negocio: rogue APs, aislamiento de clientes, credenciales del router, dispositivos expuestos, cumplimiento PCI DSS.',
      price: '399 € + IVA',
    },
    {
      name: 'PREMIUM — Auditoría Completa',
      description: 'Paquete Estándar + WiFi + análisis de red interna + informe ejecutivo personalizado.',
      price: '999 € + IVA',
    },
    {
      name: 'MANTENIMIENTO MENSUAL',
      description: 'Monitorización continua, alertas de nuevas vulnerabilidades, 1 revisión trimestral.',
      price: '99 €/mes + IVA',
    },
  ];

  const rows = [
    // Header row
    new TableRow({
      height: { value: 400, rule: 'atLeast' },
      children: [
        new TableCell({
          shading: { fill: PURPLE, type: ShadingType.CLEAR },
          children: [
            new Paragraph({
              text: 'Paquete',
              runs: [
                new TextRun({
                  text: 'Paquete',
                  bold: true,
                  color: 'FFFFFF',
                  size: 20,
                  font: 'Arial',
                }),
              ],
              alignment: AlignmentType.CENTER,
            }),
          ],
          margins: { top: 100, bottom: 100, left: 100, right: 100 },
          verticalAlign: VerticalAlign.CENTER,
        }),
        new TableCell({
          shading: { fill: PURPLE, type: ShadingType.CLEAR },
          children: [
            new Paragraph({
              text: 'Qué incluye',
              runs: [
                new TextRun({
                  text: 'Qué incluye',
                  bold: true,
                  color: 'FFFFFF',
                  size: 20,
                  font: 'Arial',
                }),
              ],
              alignment: AlignmentType.CENTER,
            }),
          ],
          margins: { top: 100, bottom: 100, left: 100, right: 100 },
          verticalAlign: VerticalAlign.CENTER,
        }),
        new TableCell({
          shading: { fill: PURPLE, type: ShadingType.CLEAR },
          children: [
            new Paragraph({
              text: 'Precio',
              runs: [
                new TextRun({
                  text: 'Precio',
                  bold: true,
                  color: 'FFFFFF',
                  size: 20,
                  font: 'Arial',
                }),
              ],
              alignment: AlignmentType.CENTER,
            }),
          ],
          margins: { top: 100, bottom: 100, left: 100, right: 100 },
          verticalAlign: VerticalAlign.CENTER,
        }),
      ],
    }),
  ];

  // Data rows
  services.forEach((service, index) => {
    const bgColor = index % 2 === 0 ? LIGHT_BG : 'FFFFFF';

    rows.push(
      new TableRow({
        height: { value: 600, rule: 'atLeast' },
        children: [
          new TableCell({
            shading: { fill: bgColor, type: ShadingType.CLEAR },
            children: [
              new Paragraph({
                text: service.name,
                runs: [
                  new TextRun({
                    text: service.name,
                    bold: true,
                    size: 18,
                    color: PURPLE,
                    font: 'Arial',
                  }),
                ],
              }),
            ],
            margins: { top: 100, bottom: 100, left: 100, right: 100 },
            verticalAlign: VerticalAlign.TOP,
            width: { size: 25, type: 'pct' },
          }),
          new TableCell({
            shading: { fill: bgColor, type: ShadingType.CLEAR },
            children: [
              new Paragraph({
                text: service.description,
                runs: [
                  new TextRun({
                    text: service.description,
                    size: 18,
                    font: 'Arial',
                  }),
                ],
              }),
            ],
            margins: { top: 100, bottom: 100, left: 100, right: 100 },
            verticalAlign: VerticalAlign.TOP,
            width: { size: 50, type: 'pct' },
          }),
          new TableCell({
            shading: { fill: bgColor, type: ShadingType.CLEAR },
            children: [
              new Paragraph({
                text: service.price,
                runs: [
                  new TextRun({
                    text: service.price,
                    bold: true,
                    size: 18,
                    color: PURPLE,
                    font: 'Arial',
                  }),
                ],
                alignment: AlignmentType.CENTER,
              }),
            ],
            margins: { top: 100, bottom: 100, left: 100, right: 100 },
            verticalAlign: VerticalAlign.CENTER,
            width: { size: 25, type: 'pct' },
          }),
        ],
      })
    );
  });

  return new Table({
    rows: rows,
    width: { size: 100, type: 'pct' },
  });
}

// Generar el archivo
Packer.toBuffer(doc).then((buffer) => {
  fs.writeFileSync('/sessions/amazing-laughing-wozniak/mnt/Termux_Purple_Team/plantillas/catalogo_servicios.docx', buffer);
  console.log('Documento creado exitosamente en: /sessions/amazing-laughing-wozniak/mnt/Termux_Purple_Team/plantillas/catalogo_servicios.docx');
});
