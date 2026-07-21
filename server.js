const pool = require("./database");

const bcrypt = require("bcrypt");

const jsonwebtoken = require("jsonwebtoken");

const { verifyToken, verifyLecturer, verifyAdmin } = require("./malware");

const SendMail = require("./emailService");

const crypto = require("crypto");

const express = require("express");

const app = express();

const cors = require("cors");

const port = 3000;

app.use(cors({ origin: "http://localhost:5173" }));

const { v4: uuidv4 } = require("uuid");
const { error } = require("console");
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ message: "Attendance server is running" });
});

app.post("/session/start", verifyToken, verifyLecturer, async (req, res) => {
  const { module_id } = req.body;

  const sessionCode = uuidv4().slice(0, 8).toUpperCase();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  try {
    const result = await pool.query(
      `INSERT INTO sessions (module_id, session_code, expires_at)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [module_id, sessionCode, expiresAt],
    );

    const sessionId = result.rows[0].id;

    const studentsResult = await pool.query(
      `SELECT id
       FROM students
       WHERE program_id = (
         SELECT program_id
         FROM modules
         WHERE id = $1
       )`,
      [module_id],
    );

    for (const student of studentsResult.rows) {
      await pool.query(
        `INSERT INTO attendance
         (session_id, student_id, status)
         VALUES ($1, $2, 'absent')`,
        [sessionId, student.id],
      );
    }

    res.json({
      message: "Session started",
      session: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({
      message: "Error starting session",
      error: err.message,
    });
  }
});

app.post("/attendance/mark", verifyToken, async (req, res) => {
  const { session_code } = req.body;
  const student_id = req.user.id;

  try {
    const session = await pool.query(
      `SELECT * FROM sessions WHERE session_code = $1`,
      [session_code],
    );

    if (session.rows.length === 0) {
      return res.status(404).json({
        message: "Invalid session code",
      });
    }

    const now = new Date();
    const expiry = new Date(session.rows[0].expires_at);

    if (now > expiry) {
      return res.status(400).json({
        message:
          "QR code has expired. Ask your lecturer to generate a new one.",
      });
    }

    const attendanceResult = await pool.query(
      `UPDATE attendance
       SET status = 'present',
           marked_at = CURRENT_TIMESTAMP
       WHERE session_id = $1
       AND student_id = $2
       RETURNING *`,
      [session.rows[0].id, student_id],
    );

    if (attendanceResult.rows.length === 0) {
      return res.status(404).json({
        message: "Attendance record not found for this student.",
      });
    }

    res.json({
      message: "Attendance marked successfully",
      attendance: attendanceResult.rows[0],
    });
  } catch (err) {
    res.status(500).json({
      message: "Error while marking attendance",
      error: err.message,
    });
  }
});

app.post("/student/register", async (req, res) => {
  const {
    registration_number,
    first_name,
    last_name,
    email,
    password,
    program_id,
  } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO students(registration_number, first_name, last_name, email, password, program_id) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [
        registration_number,
        first_name,
        last_name,
        email,
        hashedPassword,
        program_id,
      ],
    );

    res.json({
      message: "Student registered successfully",
      student: result.rows[0],
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({
        message:
          "A student with that email or registration number already exists.",
      });
    }
    res
      .status(500)
      .json({ message: "Error registering student", error: err.message });
  }
});

app.post("/student/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM students WHERE email = $1`, [
      email,
    ]);

    if (result.rows.length == 0) {
      return res.status(401).json({ message: "invalid email or password" });
    }

    const student = result.rows[0];

    const comparePassword = await bcrypt.compare(password, student.password);

    if (!comparePassword) {
      return res.status(401).json({ message: "incorrect password" });
    }

    const token = jsonwebtoken.sign(
      {
        id: student.id,
        email: student.email,
        first_name: student.first_name,
        last_name: student.last_name,
        role: "student",
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" },
    );

    res.json({
      message: "Student login successifully",
      token: token,
    });
  } catch (err) {
    res.status(500).json({ message: "error while logging in ", error: err });
  }
});

app.post("/lecturer/register", async (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO lecturers(first_name, last_name, email, password) VALUES($1, $2, $3, $4) RETURNING *`,
      [first_name, last_name, email, hashedPassword],
    );

    res.json({
      message: "lecturer registered successifully",
      lecturer: result.rows[0],
    });
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ message: "Error registering lecturer", error: err.message });
  }
});

app.post("/lecturer/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM lecturers WHERE email= $1`, [
      email,
    ]);

    if (result.rows.length == 0) {
      return res.status(404).json({ message: "lecturer not found" });
    }

    const lecturer = result.rows[0];

    const matchpassword = await bcrypt.compare(password, lecturer.password);

    if (!matchpassword)
      return res.status(401).json({ message: "incorrect password" });

    const token = jsonwebtoken.sign(
      {
        id: lecturer.id,
        email: lecturer.email,
        first_name: `${lecturer.first_name[0]}.`,
        last_name: lecturer.last_name,
        role: "lecturer",
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" },
    );

    res.json({
      message: "login successifully",
      token: token,
    });
  } catch (err) {
    res.status(500).json({
      message: "error while logging in ",
      error: err.message,
    });
  }
});

app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM admins WHERE email = $1`, [
      email,
    ]);

    if (result.rows.length == 0) {
      return res.status(404).json({ message: "admin not found" });
    }

    const admin = result.rows[0];

    const matchpassword = await bcrypt.compare(password, admin.password);

    if (!matchpassword) {
      return res.status(401).json({ message: "incorrect password" });
    }

    const token = jsonwebtoken.sign(
      {
        id: admin.id,
        email: admin.emai,
        role: "admin",
        first_name: admin.first_name,
        last_name: admin.last_name,
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" },
    );
    res.json({
      message: "admin logged in successifully",
      token: token,
    });
  } catch (err) {
    res.status(500).json({ message: "error while logging in", error: err });
  }
});

app.post(
  "/admin/create-lecturer",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    const { first_name, last_name, email, password } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await pool.query(
        `INSERT INTO lecturers (first_name, last_name, email, password)
             VALUES ($1, $2, $3, $4) RETURNING *`,
        [first_name, last_name, email, hashedPassword],
      );

      res.json({
        message: "Lecturer created successfully",
        lecturer: result.rows[0],
      });
    } catch (err) {
      if (err.code === "23505") {
        return res
          .status(400)
          .json({ message: "A lecturer with that email already exists." });
      }
      res
        .status(500)
        .json({ message: "Error creating lecturer", error: err.message });
    }
  },
);

app.post(
  "/session/:sessionId/end",
  verifyToken,
  verifyLecturer,
  async (req, res) => {
    const { sessionId } = req.params;

    try {
      const presentResult = await pool.query(
        `SELECT COUNT(*) FROM attendance WHERE session_id = $1 AND status = 'present'`,
        [sessionId],
      );

      const absentResult = await pool.query(
        `SELECT COUNT(*) FROM attendance WHERE session_id = $1 AND status = 'absent'`,
        [sessionId],
      );

      res.json({
        message: "Session ended successfully",
        totalPresent: parseInt(presentResult.rows[0].count),
        totalAbsent: parseInt(absentResult.rows[0].count),
      });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Error ending session", error: err.message });
    }
  },
);

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const studentResult = await pool.query(
      `SELECT email FROM students WHERE email = $1`,
      [email],
    );

    if (studentResult.rows.length == 0) {
      return res.status(404).json("user not found");
    }
    const token = crypto.randomBytes(32).toString("hex");

    const expiry = new Date(Date.now() + 60 * 60 * 1000);
    const insertResult = await pool.query(
      `UPDATE students SET reset_token = $2, reset_token_expiry = $3 WHERE email = $1 `,
      [email, token, expiry],
    );
    const resetLink = `http://localhost:5173/reset/password?token=${token}`;
    const message = `
    <h2>Password Reset Link</h2>
    <p>click the link below to reset your password. this link will expire in 1 hour</p>
    <a href = ${resetLink}>Reset Password</a>
    <h4>If you did not send an email please ignore this</h4>
    `;
    await SendMail(
      studentResult.rows[0].email,
      "password reset link ",
      message,
    );
    console.log("Student result:", studentResult.rows);
    res.json({
      message: "password reset link sent to your email",
      token: token,
    });
  } catch (err) {
    res.status(500).json({
      message: "error while sending the link",
      error: err.message,
    });
  }
});

app.post("/reset/password", async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const resetPasswordResult = await pool.query(
      `SELECT * FROM students WHERE reset_token = $1`,
      [token],
    );

    if (resetPasswordResult.rows.length == 0) {
      return res.status(404).json("user not found");
    }

    const student = resetPasswordResult.rows[0];

    if (new Date() > new Date(student.reset_token_expiry)) {
      return res.status(400).json({ message: "Reset link has expired." });
    }

    const hashedNewpassword = await bcrypt.hash(newPassword, 12);

    const reset = await pool.query(
      `UPDATE students SET password = $2 WHERE reset_token = $1`,
      [token, hashedNewpassword],
    );
    await pool.query(
      `UPDATE students SET reset_token=NULL, reset_token_expiry=NULL WHERE reset_token=$1`,
      [token],
    );
    res.json({
      message: "password changed successifully",
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "error while changing password", error: err.message });
  }
});
app.get("/admin/lecturers", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, first_name, last_name, email, created_at 
             FROM lecturers ORDER BY first_name`,
    );

    res.json({
      message: "Lecturers retrieved successfully",
      total: result.rows.length,
      lecturers: result.rows,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error retrieving lecturers", error: err.message });
  }
});

app.get("/admin/students", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
                students.id,
                students.first_name,
                students.last_name,
                students.email,
                students.registration_number,
                programs.name AS program_name,
                students.created_at
             FROM students
             JOIN programs ON students.program_id = programs.id
             ORDER BY students.first_name`,
    );

    res.json({
      message: "Students retrieved successfully",
      total: result.rows.length,
      students: result.rows,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error retrieving students", error: err.message });
  }
});

app.get("/session/:sessionId/attendance", verifyToken, async (req, res) => {
  const { sessionId } = req.params;

  try {
    const result = await pool.query(
      `SELECT 
            students.registration_number,
            students.first_name,
            students.last_name,
            attendance.marked_at
        FROM attendance
        JOIN students ON attendance.student_id = students.id
        WHERE attendance.session_id = $1`,
      [sessionId],
    );

    res.json({
      message: "Attendance retrieved succesifully",
      total: result.rows.length,
      attendance: result.rows,
    });
    console.log(result);
  } catch (err) {
    res.status(500).json({
      message: "error while retrieving attendance list",
      error: err.message,
    });
  }
});

app.get("/student/attendance/:moduleId", verifyToken, async (req, res) => {
  const studentId = req.user.id;
  const { moduleId } = req.params;
  try {
    const result = await pool.query(
      `SELECT 
                modules.name AS module_name,
                sessions.created_at AS session_date,
                attendance.status,
                attendance.marked_at
             FROM attendance
             JOIN sessions ON attendance.session_id = sessions.id
             JOIN modules ON sessions.module_id = modules.id
             WHERE attendance.student_id = $1 AND modules.id = $2`,
      [studentId, moduleId],
    );

    res.json({
      message: "Attendance record retrieved successfully",
      total: result.rows.length,
      attendance: result.rows,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error retrieving attendance", error: err.message });
  }
});

app.get("/student/modules", verifyToken, async (req, res) => {
  const studentId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT 
        modules.id,
        modules.name AS module_name,
        COUNT(CASE WHEN attendance.status = 'present' THEN 1 END) AS total_present,
        COUNT(CASE WHEN attendance.status = 'absent' THEN 1 END) AS total_absent,
        COUNT(attendance.id) AS total_sessions
       FROM attendance
       JOIN sessions ON attendance.session_id = sessions.id
       JOIN modules ON sessions.module_id = modules.id
       WHERE attendance.student_id = $1
       GROUP BY modules.id, modules.name`,
      [studentId],
    );

    res.json({
      message: "Modules retrieved successfully",
      modules: result.rows,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error retrieving modules", error: err.message });
  }
});

app.get(
  "/module/:moduleId/sessions",
  verifyToken,
  verifyLecturer,
  async (req, res) => {
    const { moduleId } = req.params;

    try {
      const result = await pool.query(
        `SELECT 
                sessions.id,
                sessions.session_code,
                sessions.expires_at,
                sessions.created_at,
                COUNT(attendance.id) AS total_present
             FROM sessions
             LEFT JOIN attendance ON attendance.session_id = sessions.id
             WHERE sessions.module_id = $1
             GROUP BY sessions.id`,
        [moduleId],
      );

      res.json({
        message: "Sessions retrieved successfully",
        total: result.rows.length,
        sessions: result.rows,
      });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Error retrieving sessions", error: err.message });
    }
  },
);

app.get("/schools", async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM schools ORDER BY name`);
    res.json({ schools: result.rows });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching schools", error: err.message });
  }
});

app.get("/departments/:schoolId", async (req, res) => {
  const { schoolId } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM departments WHERE school_id = $1 ORDER BY name`,
      [schoolId],
    );
    res.json({ departments: result.rows });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching departments", error: err.message });
  }
});

app.get("/programs/:departmentId", async (req, res) => {
  const { departmentId } = req.params;
  try {
    const result = await pool.query(
      `SELECT * FROM programs WHERE department_id = $1 ORDER BY name`,
      [departmentId],
    );
    res.json({ programs: result.rows });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching programs", error: err.message });
  }
});

app.get("/lecturer/modules", verifyToken, verifyLecturer, async (req, res) => {
  const lecturerId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT * FROM modules WHERE lecturer_id= $1`,
      [lecturerId],
    );
    res.json({
      message: "modules retrieved successsfully",
      modules: result.rows,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "error while getting modules ", error: err.message });
  }
});
app.listen(port, () => {
  console.log(`server running at port ${port}`);
});
